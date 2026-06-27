#pragma once

/**
 * @file udp_transport.h
 * @brief The real UDP socket behind the DHT's Transport interface.
 *
 * Owns one single-family UDP socket. send() is what dht::Node uses to put datagrams
 * on the wire; recv() is the blocking-with-timeout read the DhtRunner loop pumps.
 * Pure I/O — no DHT logic lives here.
 */

#include "core/socket.h"
#include "dht/transport.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace librats {
namespace dht {

class UdpTransport : public Transport {
public:
    // Binds a UDP socket on `port` (0 = ephemeral) for `family`. If the requested
    // port is taken it falls back to an ephemeral one. Check is_open() after.
    UdpTransport(int port, const std::string& bind_address, AddressFamily family);
    ~UdpTransport() override;

    bool     is_open() const noexcept { return is_valid_socket(socket_); }
    uint16_t port() const noexcept { return port_; }   // actual bound port

    void send(const Address& to, const std::vector<uint8_t>& datagram) override;

    // Wait up to timeout_ms for a datagram. Returns the payload and fills `from` on
    // success, or nullopt on timeout / error. If `interrupt_fd` is a valid socket it is
    // watched alongside the data socket: when it becomes readable the wait returns early
    // (as nullopt), letting the caller react to posted work without waiting out the timeout.
    std::optional<std::vector<uint8_t>> recv(int timeout_ms, Address& from,
                                             socket_t interrupt_fd = INVALID_SOCKET_VALUE);

    void close();

private:
    socket_t      socket_ = INVALID_SOCKET_VALUE;
    AddressFamily family_;
    uint16_t      port_ = 0;
};

} // namespace dht
} // namespace librats
