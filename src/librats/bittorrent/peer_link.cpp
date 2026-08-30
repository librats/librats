#include "librats/bittorrent/peer_link.h"

#include "librats/bittorrent/utp_manager.h"

#include <cerrno>

namespace librats::bittorrent {

namespace {

#ifdef _WIN32
inline bool would_block() { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
inline bool would_block() { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif

} // namespace

// ---- TcpPeerLink -------------------------------------------------------------

TcpPeerLink::TcpPeerLink(Reactor& reactor, socket_t sock) : reactor_(reactor), sock_(sock) {}

TcpPeerLink::~TcpPeerLink() {
    close();
}

void TcpPeerLink::start(Observer* obs) {
    obs_ = obs;
    set_socket_nonblocking(sock_);
    reactor_.add(sock_, PollIn, [this](std::uint32_t ev) { on_io(ev); });
}

void TcpPeerLink::on_io(std::uint32_t events) {
    // The observer may close us from inside any of these, which clears obs_ — so
    // each step re-checks rather than assuming the link is still alive.
    if ((events & PollOut) && obs_ != nullptr) obs_->on_link_writable();
    if ((events & PollIn) && obs_ != nullptr) obs_->on_link_readable();
    if ((events & (PollErr | PollHup)) && obs_ != nullptr) obs_->on_link_error("socket error");
}

PeerLink::IoResult TcpPeerLink::read(ByteSpan into) {
    if (!is_valid_socket(sock_)) return {0, Status::Error};
    const int n = ::recv(sock_, reinterpret_cast<char*>(into.data()),
                         static_cast<int>(into.size()), 0);
    if (n == 0) return {0, Status::Closed};
    if (n < 0) return {0, would_block() ? Status::WouldBlock : Status::Error};
    return {std::size_t(n), Status::Ok};
}

PeerLink::IoResult TcpPeerLink::write(const ByteView* slices, std::size_t count) {
    if (!is_valid_socket(sock_)) return {0, Status::Error};
    const std::ptrdiff_t n = send_vectored(sock_, slices, count);
    if (n > 0) return {std::size_t(n), Status::Ok};
    // Zero accepted is not an error: the socket buffer is full right now. Treated
    // the same as would-block, i.e. retry when the poller says we may.
    if (n == 0) return {0, Status::WouldBlock};
    return {0, would_block() ? Status::WouldBlock : Status::Error};
}

void TcpPeerLink::want_write(bool on) {
    if (on == want_write_ || !is_valid_socket(sock_)) return;
    want_write_ = on;
    reactor_.modify(sock_, PollIn | (on ? PollOut : PollNone));
}

void TcpPeerLink::close() {
    obs_ = nullptr;
    if (!is_valid_socket(sock_)) return;
    reactor_.remove(sock_);
    close_socket(sock_);
    sock_ = RATS_INVALID_SOCKET;
}

// ---- UtpPeerLink -------------------------------------------------------------

UtpPeerLink::UtpPeerLink(utp::Manager& manager, utp::Stream& stream)
    : manager_(manager), stream_(&stream) {}

UtpPeerLink::~UtpPeerLink() {
    close();
}

void UtpPeerLink::start(PeerLink::Observer* obs) {
    obs_ = obs;
    if (stream_ != nullptr) stream_->set_observer(this);
}

PeerLink::IoResult UtpPeerLink::read(ByteSpan into) {
    if (stream_ == nullptr) return {0, Status::Error};
    const auto r = stream_->read(into);
    switch (r.status) {
        case utp::Stream::Status::Ok:         return {r.bytes, Status::Ok};
        case utp::Stream::Status::WouldBlock: return {0, Status::WouldBlock};
        case utp::Stream::Status::Eof:        return {0, Status::Closed};
        case utp::Stream::Status::Error:      break;
    }
    return {0, Status::Error};
}

PeerLink::IoResult UtpPeerLink::write(const ByteView* slices, std::size_t count) {
    if (stream_ == nullptr) return {0, Status::Error};
    const auto r = stream_->write(slices, count, utp::Stream::Clock::now());
    switch (r.status) {
        case utp::Stream::Status::Ok:         return {r.bytes, Status::Ok};
        case utp::Stream::Status::WouldBlock: return {0, Status::WouldBlock};
        case utp::Stream::Status::Eof:
        case utp::Stream::Status::Error:      break;
    }
    return {0, Status::Error};
}

void UtpPeerLink::close() {
    obs_ = nullptr;
    if (stream_ == nullptr) return;
    // Hand it back rather than delete it: the stream still owes the peer a FIN, and
    // the manager keeps it alive just long enough to deliver one.
    utp::Stream* s = stream_;
    stream_        = nullptr;
    manager_.release(*s);
}

void UtpPeerLink::on_utp_readable() {
    if (obs_ != nullptr) obs_->on_link_readable();
}

void UtpPeerLink::on_utp_writable() {
    if (obs_ != nullptr && want_write_) obs_->on_link_writable();
}

void UtpPeerLink::on_utp_error(const std::string& why) {
    if (obs_ != nullptr) obs_->on_link_error(why);
}

} // namespace librats::bittorrent
