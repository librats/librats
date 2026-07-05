#include "dht/udp_transport.h"

namespace librats {
namespace dht {

UdpTransport::UdpTransport(int port, const std::string& bind_address, AddressFamily family)
    : family_(family) {
    init_socket_library();  // idempotent

    socket_ = create_udp_socket(port, bind_address, family_);
    if (!is_valid_socket(socket_) && port > 0) {
        // A specific port was requested but unavailable — fall back to an ephemeral one.
        // (A negative/invalid port is a hard error, not a fallback case.)
        socket_ = create_udp_socket(0, bind_address, family_);
    }
    if (is_valid_socket(socket_)) {
        port_ = static_cast<uint16_t>(get_bound_port(socket_));
        set_socket_nonblocking(socket_);  // recv() drives readiness via its timeout
    }
}

UdpTransport::~UdpTransport() {
    close();
}

void UdpTransport::send(const Address& to, const std::vector<uint8_t>& datagram) {
    if (!is_open()) return;
    send_udp_data(socket_, datagram, to, family_);
}

std::optional<std::vector<uint8_t>> UdpTransport::recv(int timeout_ms, Address& from,
                                                       socket_t interrupt_fd) {
    if (!is_open()) return std::nullopt;
    // 4 KiB comfortably covers any KRPC datagram; an oversized one would be dropped
    // (truncated to WSAEMSGSIZE on Windows), so leave headroom above the ~1500 MTU.
    auto data = receive_udp_data(socket_, 4096, from, timeout_ms, interrupt_fd);
    if (data.empty()) return std::nullopt;
    return data;
}

void UdpTransport::close() {
    if (is_valid_socket(socket_)) {
        close_socket(socket_);
        socket_ = INVALID_SOCKET_VALUE;
    }
}

} // namespace dht
} // namespace librats
