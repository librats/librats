#include "librats/transport/relay_link.h"

#include "librats/core/io_poller.h"   // PollIn / PollOut / PollErr
#include "librats/util/logger.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace librats {

namespace {

/// Slices one data message gathers from the caller's list. The send buffer hands
/// out a length prefix and a body per queued frame, so this covers a run of frames
/// rather than a single one; a longer backlog than this simply comes back on the
/// next turn of Connection::flush.
constexpr size_t kMaxParts = 16;

} // namespace

Circuit::Circuit(uint32_t id, std::shared_ptr<CircuitCarrier> carrier, bool open,
                 uint32_t recv_window, uint32_t peer_window)
    : id_(id),
      carrier_(std::move(carrier)),
      state_(open ? State::Open : State::Pending),
      recv_window_(recv_window == 0 ? kDefaultWindow : recv_window),
      send_credit_(open ? peer_window : 0) {}

std::shared_ptr<Circuit> Circuit::opening(uint32_t id, std::shared_ptr<CircuitCarrier> carrier,
                                          uint32_t recv_window) {
    return std::shared_ptr<Circuit>(
        new Circuit(id, std::move(carrier), /*open=*/false, recv_window, /*peer_window=*/0));
}

std::shared_ptr<Circuit> Circuit::accepted(uint32_t id, std::shared_ptr<CircuitCarrier> carrier,
                                           uint32_t peer_window, uint32_t recv_window) {
    return std::shared_ptr<Circuit>(
        new Circuit(id, std::move(carrier), /*open=*/true, recv_window, peer_window));
}

// ── Fed by the relay module ─────────────────────────────────────────────────

uint32_t Circuit::on_data(ByteView bytes) {
    if (state_ == State::Closed || bytes.empty()) return 0;

    // The window is the ONE thing bounding what this circuit can cost us and the
    // relay carrying it, so a peer that sends past what it was granted is not
    // merely impolite — it is doing the thing the window exists to prevent. Fail
    // the circuit rather than accept the bytes.
    if (bytes.size() > recv_window_ - recv_in_flight_) {
        LOG_WARN("relay", "Circuit " << id_ << " overran its receive window ("
                 << bytes.size() << " B with " << (recv_window_ - recv_in_flight_)
                 << " B granted); failing it");
        return on_closed(CloseReason::ProtocolError, /*orderly=*/false);
    }
    recv_in_flight_ += static_cast<uint32_t>(bytes.size());

    // Hand back the consumed prefix before growing: the connection normally drains
    // the inbox to empty on every readable event, so this is nearly always a reset
    // of an already-empty buffer rather than a move.
    if (inbox_read_ == inbox_.size()) {
        inbox_.clear();
        inbox_read_ = 0;
    } else if (inbox_read_ >= kCompactThreshold) {
        inbox_.erase(inbox_.begin(), inbox_.begin() + static_cast<std::ptrdiff_t>(inbox_read_));
        inbox_read_ = 0;
    }

    inbox_.insert(inbox_.end(), bytes.begin(), bytes.end());
    return PollIn;
}

uint32_t Circuit::on_accept(uint32_t peer_window) {
    if (state_ != State::Pending) return 0;
    state_       = State::Open;
    send_credit_ = peer_window;
    // Unconditional, unlike the other openings below: the Connection is still in
    // Connecting and has nothing queued, so want_write_ is false — yet this is
    // precisely the event it is waiting for to finish connecting and start its
    // handshake (see Connection::on_writable).
    return PollOut;
}

uint32_t Circuit::on_credit(uint32_t bytes) {
    if (state_ == State::Closed || bytes == 0) return 0;
    // Saturate rather than wrap: a far end that grants nonsense should cost us
    // nothing worse than an over-generous window, and the receiver's own window
    // check is what actually bounds the traffic.
    if (bytes > UINT32_MAX - send_credit_) send_credit_ = UINT32_MAX;
    else                                   send_credit_ += bytes;

    if (!credit_blocked_) return 0;
    credit_blocked_ = false;
    return writable_event();
}

uint32_t Circuit::on_closed(CloseReason reason, bool orderly) {
    if (state_ == State::Closed) return 0;
    state_   = State::Closed;
    reason_  = reason;
    orderly_ = orderly;
    // An orderly close still owes the application whatever the far end sent before
    // it: read() drains the inbox first and only then reports the end of stream, so
    // what this needs is a readable event, not an error. That is the same contract
    // the other links keep (see Link::read).
    return orderly ? PollIn : PollErr;
}

uint32_t Circuit::on_carrier_writable() {
    if (!carrier_blocked_) return 0;
    carrier_blocked_ = false;
    return writable_event();
}

uint32_t Circuit::writable_event() const noexcept {
    if (blocked() || !want_write_ || state_ != State::Open) return 0;
    return PollOut;
}

// ── Driven by the Connection ────────────────────────────────────────────────

Link::IoResult Circuit::read(ByteSpan into) {
    const size_t available = inbox_.size() - inbox_read_;
    const size_t n = (std::min)(available, into.size());
    if (n > 0) {
        std::memcpy(into.data(), inbox_.data() + inbox_read_, n);
        inbox_read_ += n;
        if (inbox_read_ == inbox_.size()) {
            inbox_.clear();
            inbox_read_ = 0;
        }

        // These bytes are out of the pipe, so the far end may put that much back
        // in. Granted in batches: one small message per half-window rather than one
        // per chunk, which is what keeps the credit scheme's overhead invisible.
        recv_in_flight_ -= static_cast<uint32_t>(n);
        recv_ungranted_ += static_cast<uint32_t>(n);
        if (state_ != State::Closed && recv_ungranted_ >= recv_window_ / kCreditGrantFraction) {
            carrier_->circuit_send_credit(id_, recv_ungranted_);
            recv_ungranted_ = 0;
        }
        return {n, Link::Status::Ok};
    }

    // Drained. Only now may the end of the stream be reported — data and
    // end-of-stream are never delivered together.
    if (state_ == State::Closed)
        return {0, orderly_ ? Link::Status::Closed : Link::Status::Error};
    return {0, Link::Status::WouldBlock};
}

Link::IoResult Circuit::write(const ByteView* slices, size_t count) {
    if (state_ == State::Closed) return {0, Link::Status::Error};
    // Pending: opened but not yet accepted. Nothing may go out — and nothing tries
    // to, since the Connection is still Connecting.
    if (state_ != State::Open) return {0, Link::Status::WouldBlock};
    if (blocked())             return {0, Link::Status::WouldBlock};

    const size_t budget = (std::min)(static_cast<size_t>(send_credit_), kMaxDataChunk);
    if (budget == 0) {
        credit_blocked_ = true;
        return {0, Link::Status::WouldBlock};
    }

    // One data message per call, gathered across as many of the caller's slices as
    // fit. Connection::flush loops while a link keeps reporting Ok, so a backlog
    // larger than one chunk simply comes back around — no loop is needed here, and
    // each turn of that loop re-checks the credit and the carrier.
    ByteView parts[kMaxParts];
    size_t   nparts = 0;
    size_t   taken  = 0;
    for (size_t i = 0; i < count && taken < budget && nparts < kMaxParts; ++i) {
        if (slices[i].empty()) continue;
        const size_t take = (std::min)(slices[i].size(), budget - taken);
        parts[nparts++] = ByteView(slices[i].data(), take);
        taken += take;
    }
    if (taken == 0) return {0, Link::Status::WouldBlock};

    send_credit_ -= static_cast<uint32_t>(taken);
    // The carrier queues what it is given either way; false is "stop and wait", so
    // the bytes are ours to report as written and the block applies to the NEXT
    // call (see CircuitCarrier::circuit_send_data).
    if (!carrier_->circuit_send_data(id_, parts, nparts)) carrier_blocked_ = true;
    return {taken, Link::Status::Ok};
}

void Circuit::shutdown(CloseReason reason) {
    if (!close_sent_) {
        close_sent_ = true;
        carrier_->circuit_send_close(id_, reason);
    }
    if (state_ != State::Closed) {
        state_   = State::Closed;
        reason_  = reason;
        orderly_ = false;
    }
}

void Circuit::release() {
    if (released_) return;
    released_ = true;
    state_    = State::Closed;
    carrier_->circuit_released(id_);
}

} // namespace librats
