#include "core/connection.h"
#include "core/reactor.h"
#include "io_poller.h"
#include "logger.h"

#include <cerrno>
#include <cstring>

namespace librats {

namespace {

constexpr size_t kRecvChunk    = 16 * 1024;  ///< bytes offered to each recv()
constexpr size_t kCompactWaste = 64 * 1024;  ///< compact rx_ past this front waste

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

    queue_block(cipher);

    if (tx_.size() > send_high_water_) {
        LOG_WARN("connection", "Peer " << remote_id_.short_hex() << " over send high-water ("
                 << tx_.size() << " B); closing as slow consumer");
        close_reason_ = CloseReason::SlowConsumer;
        state_ = ConnState::Closing;
        reactor_.close(id_, CloseReason::SlowConsumer);
        return;
    }
    // Write-through: try to send now rather than waiting for a PollOut event.
    if (!flush()) reactor_.close(id_, close_reason_);
}

void Connection::queue_block(ByteView body) {
    Bytes block;
    framer::encode_block(block, body);
    tx_.append(std::move(block));
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
        queue_block(out);   // initiator's first message
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
        queue_block(out);   // reply (e.g. responder's message, or initiator's final)
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

void Connection::complete_established() {
    state_ = ConnState::Established;
    if (establish_timer_ != kInvalidTimerId) {
        reactor_.cancel(establish_timer_);
        establish_timer_ = kInvalidTimerId;
    }
    LOG_DEBUG("connection", "Peer " << remote_id_.short_hex() << " established ("
              << (role_ == ConnRole::Inbound ? "inbound" : "outbound")
              << (is_secure() ? ", encrypted)" : ", plaintext)"));
    delegate_.on_established(*this);
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

    // Process every complete block. Body views point into rx_, so each block
    // must be consumed before decoding the next.
    while (rx_.size() > 0) {
        auto block = framer::try_take_block(rx_.data(), rx_.size());
        if (block.status == framer::Block::Incomplete) break;
        if (block.status == framer::Block::Error) return fail(CloseReason::ProtocolError);

        bool keep = (state_ == ConnState::Handshaking) ? drive_handshake(block.body)
                                                        : deliver_frame(block.body);
        rx_.consume(block.consumed);
        if (!keep) return false;
        if (state_ == ConnState::Closing || state_ == ConnState::Closed) return false;
    }

    if (rx_.front_waste() > kCompactWaste) rx_.normalize();

    if (peer_closed) return fail(CloseReason::PeerClosed);
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

bool Connection::fail(CloseReason reason) {
    close_reason_ = reason;
    state_ = ConnState::Closing;
    return false;  // tells the reactor to tear this connection down
}

} // namespace librats
