#include "librats/transport/tcp_link.h"
#include "librats/transport/reactor.h"
#include "librats/core/io_poller.h"

#include <cerrno>

namespace librats {

namespace {

#ifdef _WIN32
inline bool last_error_would_block() { return WSAGetLastError() == WSAEWOULDBLOCK; }
#else
inline bool last_error_would_block() { return errno == EAGAIN || errno == EWOULDBLOCK; }
#endif

} // namespace

Link::IoResult TcpLink::read(ByteSpan into) {
    const int n = ::recv(socket_, reinterpret_cast<char*>(into.data()),
                         static_cast<int>(into.size()), 0);
    if (n > 0) return {static_cast<size_t>(n), Status::Ok};
    if (n == 0) return {0, Status::Closed};  // FIN: the peer is done sending
    return {0, last_error_would_block() ? Status::WouldBlock : Status::Error};
}

Link::IoResult TcpLink::write(const ByteView* slices, size_t count) {
    const std::ptrdiff_t n = send_vectored(socket_, slices, count);
    if (n > 0) return {static_cast<size_t>(n), Status::Ok};
    // n == 0 means the socket accepted nothing this round — indistinguishable from
    // a full send buffer as far as the caller is concerned, so report would-block
    // and let the next writable event drive the retry.
    if (n == 0) return {0, Status::WouldBlock};
    return {0, last_error_would_block() ? Status::WouldBlock : Status::Error};
}

bool TcpLink::connect_completed() {
    return tcp_connect_result(socket_) == 0;
}

void TcpLink::want_write(bool on) {
    reactor_.set_interest(socket_, on ? (PollIn | PollOut) : static_cast<uint32_t>(PollIn));
}

std::optional<Address> TcpLink::remote_endpoint() const {
    return get_peer_endpoint(socket_);
}

} // namespace librats
