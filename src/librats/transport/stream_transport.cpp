#include "librats/transport/stream_transport.h"
#include "librats/util/logger.h"

#include <algorithm>

namespace librats {

namespace {

constexpr size_t kRecvChunk = 16 * 1024;  ///< bytes offered to each read()

/// Ceiling on how far rx_ may be grown on the strength of a *declared* block length
/// alone. Sizing the buffer for the whole block up front (as libtorrent does, growing
/// straight to packet_size) turns a large frame into one allocation instead of a
/// 1.5x-at-a-time climb that memmoves everything received so far at every step. But
/// the length is the peer's word: a 4-byte prefix claiming kMaxBlockSize must not
/// make us allocate 64 MiB for a peer that then sends nothing. Past this, growth
/// falls back to geometric, so the allocation only ever tracks bytes that really
/// arrived — a big block still costs a handful of reallocations, not tens.
constexpr size_t kMaxEagerReserve = 1024 * 1024;

} // namespace

StreamTransport::StreamTransport(std::unique_ptr<Link> link, ConnRole role,
                                 SecurityProvider& security)
    : link_(std::move(link)), role_(role), security_(security) {}

StreamTransport::~StreamTransport() = default;

void StreamTransport::attach(ConnId id, TransportSink& sink) {
    sink_ = &sink;
    link_->attach(id);
}

// ── Handshake ───────────────────────────────────────────────────────────────

bool StreamTransport::start() {
    return phase_ == Phase::Connecting ? begin_handshake() : true;
}

bool StreamTransport::begin_handshake() {
    phase_ = Phase::Handshaking;
    // The path is up, so the write interest raised for the connect itself is no
    // longer wanted; flush() raises it again if the handshake outgrows the link.
    want_write_ = false;
    link_->want_write(false);

    handshaker_ = security_.create(role_);
    Bytes out;
    if (!handshaker_->start(out)) return fail(CloseReason::HandshakeFailed);
    sink_->transport_connected();
    if (out.empty()) return true;    // the responder waits for the first message
    queue_handshake(out);
    return flush();
}

bool StreamTransport::drive_handshake(ByteView body) {
    Bytes out;
    auto outcome = handshaker_->consume(body, out);
    if (outcome.status == Handshaker::Outcome::Failed) return fail(CloseReason::HandshakeFailed);
    if (!out.empty()) {
        queue_handshake(out);   // the responder's message, or the initiator's last
        if (!flush()) return false;
    }
    if (outcome.status == Handshaker::Outcome::Done) {
        session_ = std::move(outcome.session);
        handshaker_.reset();
        queue_.set_seal_room(session_->overhead());
        phase_ = Phase::Established;   // before the sink: it may send at once
        sink_->transport_established(outcome.remote_id);
    }
    return true;
}

void StreamTransport::queue_handshake(const Bytes& message) {
    uint8_t* block = tx_.append_slot(framer::kLengthPrefixSize + message.size());
    framer::encode_block_header(block, message.size());
    std::copy(message.begin(), message.end(), block + framer::kLengthPrefixSize);
}

// ── Inbound ─────────────────────────────────────────────────────────────────

bool StreamTransport::on_readable() {
    // Drain the link, parsing as we go. The parse step is inside the loop on
    // purpose: it keeps rx_ down to one block in flight however fast the peer
    // sends, where draining first and parsing afterwards would let rx_ grow to
    // everything the peer managed to deliver.
    //
    // It must drain to would-block (or to a short read, which means the kernel
    // buffer is now empty) — the kqueue backend is edge-triggered, so stopping with
    // data still queued would leave the connection stalled until the *next* byte.
    while (true) {
        const ByteSpan into = rx_.prepare(read_size());

        const Link::IoResult r = link_->read(into);
        if (r.status == Link::Status::Closed) {
            if (!process_blocks()) return false;  // deliver what the peer sent before its FIN
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

size_t StreamTransport::read_size() const {
    // Not established yet: the peer is still anonymous, so its declared length buys it
    // nothing. A handshake block is a Noise message plus the protocol id — hundreds of
    // bytes — so there is no large allocation to save here, while honouring the length
    // would let four bytes from an unauthenticated socket reserve kMaxEagerReserve. rx_
    // still grows geometrically to hold whatever actually arrives.
    if (phase_ != Phase::Established) return kRecvChunk;

    // Ask for the rest of the block we are part-way through, so a large frame lands in
    // one allocation rather than a series of 1.5x growth steps. Bounded by
    // kMaxEagerReserve, since rx_need_ is a length the *peer* declared.
    //
    // Note this asks for the remainder even when it is *smaller* than kRecvChunk. It
    // is tempting to floor it at kRecvChunk ("read as much as we can anyway"), but
    // prepare(n) is a demand for n bytes of free tail, and a buffer sized exactly for
    // the block has no kRecvChunk of tail left near the end of it — so the floor would
    // force one last 1.5x grow (memcpy'ing the whole block that already arrived) for
    // room that the block does not need. Nothing is lost by asking for less: prepare()
    // hands back the *entire* free tail regardless, so the read is just as big.
    if (rx_need_ > rx_.size()) return (std::min)(rx_need_ - rx_.size(), kMaxEagerReserve);
    return kRecvChunk;
}

bool StreamTransport::process_blocks() {
    rx_need_ = 0;  // recomputed below: 0 == no block is part-way in

    // A block is consumed before the next one is decoded (and before any read can
    // reallocate rx_ under the views into it).
    while (!rx_.empty()) {
        const auto block = framer::try_take_block(rx_.data(), rx_.size());
        if (block.status == framer::Block::Incomplete) {
            rx_need_ = block.needed;  // 0 while even the length prefix is short
            break;
        }
        if (block.status == framer::Block::Error) return fail(CloseReason::ProtocolError);

        // Opened where it lies, so the body is reached through rx_'s writable view
        // rather than the read-only one the block carries.
        const bool keep = (phase_ == Phase::Handshaking)
            ? drive_handshake(block.body)
            : deliver(rx_.data() + framer::kLengthPrefixSize, block.body.size());
        rx_.consume(block.consumed);
        if (!keep) return false;
    }
    return true;
}

bool StreamTransport::deliver(uint8_t* body, size_t size) {
    if (!session_) return fail(CloseReason::ProtocolError);  // data before the handshake

    const auto plain = session_->open(recv_nonce_++, {}, body, size);
    if (!plain) return fail(CloseReason::ProtocolError);

    const auto msg = framer::parse_message(ByteView(body, *plain));
    if (!msg.ok) return fail(CloseReason::ProtocolError);

    // A sink that says stop is closing the connection, not reporting a broken
    // transport — so error_ is left alone and the connection's own reason stands.
    return sink_->transport_frame(msg.frame);
}

// ── Outbound ────────────────────────────────────────────────────────────────

size_t StreamTransport::max_payload() const noexcept {
    // A block tops out at kMaxBlockSize and the peer's decoder rejects anything past
    // it, so a message that does not fit one cannot be carried at all.
    const size_t framing = framer::kHeaderSize + (session_ ? session_->overhead() : 0);
    return framer::kMaxBlockSize - framing;
}

bool StreamTransport::send(FrameHeader header, ByteView payload) {
    queue_.push(header, payload);

    // Enough for a write already: send it now rather than hold it to the end of the
    // turn. Not while the link has said it is full, though — its writable event is
    // what will move things on, and a write now would only be refused.
    if (!want_write_ && queue_.size() + tx_.size() >= kCoalesceLimit) return flush();
    return true;
}

bool StreamTransport::flush() {
    for (;;) {
        // Seal only just ahead of the link. What it has not taken yet stays in the
        // queue unsealed, so a more urgent lane can still go first.
        while (tx_.size() < kSealAhead && !queue_.empty())
            queue_.seal_next(*session_, send_nonce_++, tx_);
        if (tx_.empty()) break;

        // The whole of tx_ in one write: a burst of blocks leaves in a single
        // syscall instead of one each.
        ByteView slices[kMaxSendSlices];
        const size_t count = tx_.gather(slices, kMaxSendSlices);

        const Link::IoResult r = link_->write(slices, count);
        if (r.status == Link::Status::Ok) { tx_.pop_front(r.bytes); continue; }
        if (r.status == Link::Status::WouldBlock) break;  // retried on the next writable event
        return fail(link_->error_reason());
    }
    arm_write(!tx_.empty());
    return true;
}

bool StreamTransport::on_writable() {
    // Finish the path's own connect (a non-blocking TCP connect, a Syn that has
    // just been answered, a circuit the far end accepted), then begin the handshake.
    if (phase_ == Phase::Connecting) {
        if (!link_->connect_completed()) {
            LOG_DEBUG("transport", "Connect over " << to_string(kind()) << " failed");
            return fail(CloseReason::ConnectFailed);
        }
        if (!begin_handshake()) return false;
    }
    return flush();
}

void StreamTransport::arm_write(bool on) {
    if (want_write_ == on) return;
    want_write_ = on;
    link_->want_write(on);
}

PathStats StreamTransport::path_stats() const {
    PathStats s = link_->path_stats();
    // Everything queued here waits in front of a new message as surely as what
    // the link holds — on TCP far more, the kernel's own backlog being kept short.
    if (s.valid) s.queued_bytes += queue_.size() + tx_.size();
    return s;
}

bool StreamTransport::fail(CloseReason reason) {
    error_ = reason;
    phase_ = Phase::Broken;
    return false;
}

} // namespace librats
