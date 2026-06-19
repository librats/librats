#include "core/connection.h"
#include "core/reactor.h"
#include "io_poller.h"
#include "logger.h"

#include <cerrno>
#include <cstring>

namespace librats {

namespace {

constexpr size_t kRecvChunk     = 16 * 1024;  ///< bytes offered to each recv()
constexpr size_t kCompactWaste  = 64 * 1024;  ///< compact rx_ past this front waste

#ifdef _WIN32
constexpr int kSendFlags = 0;
inline bool last_error_would_block() { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
constexpr int kSendFlags = MSG_NOSIGNAL;
inline bool last_error_would_block() { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif

} // namespace

Connection::Connection(ConnId id, socket_t sock, ConnRole role,
                       Reactor& reactor, ConnectionDelegate& delegate)
    : id_(id), socket_(sock), role_(role), reactor_(reactor), delegate_(delegate) {}

Connection::~Connection() = default;

// ── Outbound ────────────────────────────────────────────────────────────────

void Connection::send(FrameHeader header, ByteView payload) {
    if (state_ == ConnState::Closing || state_ == ConnState::Closed) return;

    Bytes frame;
    framer::encode(frame, header, payload);
    tx_.append(std::move(frame));

    if (tx_.size() > send_high_water_) {
        LOG_WARN("connection", "Peer " << id_ << " over send high-water ("
                 << tx_.size() << " B); closing as slow consumer");
        // Stop accepting more data now; defer the actual teardown to the reactor.
        close_reason_ = CloseReason::SlowConsumer;
        state_ = ConnState::Closing;
        reactor_.close(id_, CloseReason::SlowConsumer);
        return;
    }

    // While still connecting, the write will be flushed once Established.
    if (state_ == ConnState::Established) arm_write();
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

void Connection::start_established() {
    if (state_ == ConnState::Connecting) mark_established();
}

void Connection::mark_established() {
    state_ = ConnState::Established;
    want_write_ = false;
    if (connect_timer_ != kInvalidTimerId) {
        reactor_.cancel(connect_timer_);
        connect_timer_ = kInvalidTimerId;
    }
    reactor_.set_interest(socket_, PollIn);
    LOG_DEBUG("connection", "Peer " << id_ << " established ("
              << (role_ == ConnRole::Inbound ? "inbound" : "outbound") << ")");
    delegate_.on_established(*this);
    if (!tx_.empty()) arm_write();
}

bool Connection::fail(CloseReason reason) {
    close_reason_ = reason;
    state_ = ConnState::Closing;
    return false;  // tells the reactor to tear this connection down
}

// ── Inbound ─────────────────────────────────────────────────────────────────

bool Connection::on_readable() {
    bool peer_closed = false;

    // Drain the kernel buffer (the socket is non-blocking).
    while (true) {
        rx_.ensure_space(kRecvChunk);
        int n = ::recv(socket_, reinterpret_cast<char*>(rx_.write_ptr()),
                       static_cast<int>(rx_.write_space()), 0);
        if (n > 0) {
            rx_.received(static_cast<size_t>(n));
            continue;
        }
        if (n == 0) { peer_closed = true; break; }
        if (last_error_would_block()) break;
        return fail(CloseReason::PeerReset);
    }

    // Extract and dispatch every complete frame. Payload views point into rx_,
    // so each frame must be consumed before the next decode.
    while (rx_.size() > 0) {
        auto d = framer::try_decode(rx_.data(), rx_.size());
        if (d.status == framer::Decoded::Incomplete) break;
        if (d.status == framer::Decoded::Error) return fail(CloseReason::ProtocolError);

        delegate_.on_frame(*this, d.frame);
        rx_.consume(d.consumed);

        // The delegate may have closed us (e.g. SlowConsumer on a reply).
        if (state_ != ConnState::Established) return false;
    }

    if (rx_.front_waste() > kCompactWaste) rx_.normalize();

    if (peer_closed) return fail(CloseReason::PeerClosed);
    return true;
}

bool Connection::on_writable() {
    // Finish a non-blocking connect before anything else.
    if (state_ == ConnState::Connecting) {
        int err = tcp_connect_result(socket_);
        if (err != 0) {
            LOG_DEBUG("connection", "Peer " << id_ << " connect failed (err " << err << ")");
            return fail(CloseReason::ConnectFailed);
        }
        mark_established();  // may arm_write() again if tx_ has data
    }
    return flush();
}

bool Connection::on_error() {
    return fail(CloseReason::PeerReset);
}

// ── Send buffer flush + write interest ──────────────────────────────────────

bool Connection::flush() {
    while (!tx_.empty()) {
        int n = ::send(socket_, reinterpret_cast<const char*>(tx_.front_data()),
                       static_cast<int>(tx_.front_size()), kSendFlags);
        if (n > 0) { tx_.pop_front(static_cast<size_t>(n)); continue; }
        if (n == 0) break;
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

} // namespace librats
