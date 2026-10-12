#include "librats/transport/connection.h"
#include "librats/transport/reactor.h"
#include "librats/util/logger.h"

#include <algorithm>

namespace librats {

Connection::Connection(ConnId id, std::unique_ptr<Transport> transport, ConnRole role,
                       Reactor& reactor, ConnectionDelegate& delegate)
    : id_(id), transport_(std::move(transport)), role_(role), reactor_(reactor), delegate_(delegate) {
    transport_->attach(id_, *this);
}

Connection::~Connection() = default;

IpAddress Connection::remote_ip() const {
    // The peer's source IP as the transport sees it, with no textual round-trip.
    // (The source port is not dialable — ephemeral on TCP, NAT-rewritten on UDP —
    // so it is discarded; identify supplies the real listen port.)
    const auto ep = transport_->remote_endpoint();
    return ep ? ep->ip : IpAddress{};
}

uint8_t Connection::reactor_index() const noexcept { return reactor_.index(); }

PathStats Connection::sample_path() {
    PathStats s = transport_->path_stats();
    if (!s.valid) return s;
    // What is still on its way here waits in front of a new message as surely as
    // what the transport already holds.
    if (in_transit_) s.queued_bytes += in_transit_->load(std::memory_order_relaxed);

    const uint64_t delivered = s.bytes_delivered - (std::min)(sampled_delivered_, s.bytes_delivered);
    const uint64_t lost      = s.bytes_lost - (std::min)(sampled_lost_, s.bytes_lost);
    s.loss = delivered + lost ? static_cast<double>(lost) / static_cast<double>(delivered + lost) : 0.0;
    sampled_delivered_ = s.bytes_delivered;
    sampled_lost_      = s.bytes_lost;
    return s;
}

// ── Outbound application frames ─────────────────────────────────────────────

bool Connection::send(FrameHeader header, ByteView payload) {
    if (state_ != ConnState::Established) return false;  // frames only flow post-handshake

    // The one thing that is refused outright rather than queued: a message too
    // large for the transport to carry at all. Queueing it would spend the link only
    // to have the far end hang up on a protocol error it was handed on purpose, and
    // waiting cannot help either — no amount of draining makes it fit — so the
    // honest answer is a refusal, with nothing queued and the connection untouched.
    if (payload.size() > transport_->max_payload()) {
        LOG_WARN("connection", "Peer " << remote_id_.short_hex() << " refused a "
                 << payload.size() << " B message: past the " << transport_->max_payload()
                 << " B the transport can carry; split it");
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
        fail(CloseReason::SlowConsumer);
        reactor_.close(id_, CloseReason::SlowConsumer);
        return false;
    }

    if (!transport_->send(header, payload)) {
        fail(transport_->error_reason());
        reactor_.close(id_, close_reason_);
        return false;
    }

    // The queue has grown past what a caller should keep adding to. Everything
    // still goes out — nothing is dropped here — but the answer to "may I send
    // more?" becomes no, and stays no until the queue drains back under the mark
    // and on_writable_changed says so. Without this an application has no way at
    // all to tell that it is outrunning the link, and the only thing that
    // eventually tells it is the disconnection above.
    if (!over_low_water_ && backlog() > send_low_water_) {
        over_low_water_ = true;
        delegate_.on_writable_changed(*this, false);
    }

    // Aggregate rather than write through: the frames of one batch of reactor tasks
    // belong in ONE write, which the reactor makes at the end of this same turn
    // (Reactor::flush_dirty) — nothing waits on a timer. The transport writes sooner
    // by itself once that would only hold memory.
    if (!flush_queued_) {
        flush_queued_ = true;
        reactor_.mark_dirty(id_);
    }
    return !over_low_water_;
}

bool Connection::flush_pending() {
    flush_queued_ = false;
    return settle(transport_->flush());
}

// ── Reactor-driven I/O ──────────────────────────────────────────────────────

void Connection::start_handshake() {
    if (state_ != ConnState::Connecting) return;
    if (!transport_->start()) {
        fail(transport_->error_reason());
        reactor_.close(id_, close_reason_);
    }
}

bool Connection::on_readable() { return settle(transport_->on_readable()); }
bool Connection::on_writable() { return settle(transport_->on_writable()); }
bool Connection::on_error()    { return settle(transport_->on_error()); }

bool Connection::settle(bool ok) {
    if (!ok) {
        // Already closing — a send that tripped the slow-consumer mark from inside a
        // delivery — is the connection's own decision, and its reason stands.
        if (state_ == ConnState::Closing) return false;
        return fail(transport_->error_reason());
    }
    note_drained();
    return true;
}

void Connection::note_drained() {
    // Drained back under the mark: whoever was told to stop can start again. The
    // re-entrancy guard is what keeps a handler that answers by sending from
    // recursing through here — it may queue, and the next drain reports the next
    // opening, but it cannot nest.
    if (over_low_water_ && !in_writable_ && backlog() <= send_low_water_) {
        over_low_water_ = false;
        in_writable_    = true;
        delegate_.on_writable_changed(*this, true);
        in_writable_    = false;
    }
}

// ── Transport events ────────────────────────────────────────────────────────

void Connection::transport_connected() {
    state_ = ConnState::Handshaking;
}

void Connection::transport_established(const PeerId& remote) {
    state_     = ConnState::Established;
    remote_id_ = remote;
    cancel_establish_timer();
    LOG_DEBUG("connection", "Peer " << remote_id_.short_hex() << " established ("
              << (role_ == ConnRole::Inbound ? "inbound" : "outbound")
              << (is_secure() ? ", encrypted)" : ", plaintext)"));
    delegate_.on_established(*this);
}

bool Connection::transport_frame(const Frame& frame) {
    delegate_.on_frame(*this, frame);
    return state_ != ConnState::Closing && state_ != ConnState::Closed;
}

// ── Teardown ────────────────────────────────────────────────────────────────

void Connection::cancel_establish_timer() {
    if (establish_timer_ != kInvalidTimerId) {
        reactor_.cancel(establish_timer_);
        establish_timer_ = kInvalidTimerId;
    }
}

bool Connection::fail(CloseReason reason) {
    close_reason_ = reason;
    state_ = ConnState::Closing;
    return false;  // tells the reactor to tear this connection down
}

} // namespace librats
