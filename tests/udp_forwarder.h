#pragma once

/**
 * @file udp_forwarder.h
 * @brief A path between two nodes on loopback that can be cut, or moved: a UDP
 *        forwarder.
 *
 * What comes to its port goes on to `to` from a socket of its own, and what comes
 * back there goes to whoever last sent to its port. So the far end sees whoever
 * dialed through it at the forwarder's back socket — and, after move(), at
 * another one: the dialer's NAT giving it a new address. Cut, nothing passes in
 * that direction, with neither end told: a network gone, or one that lets through
 * only what goes one way.
 */

#include "librats/core/address.h"
#include "librats/core/socket.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>

namespace librats_test {

class UdpForwarder {
public:
    explicit UdpForwarder(uint16_t to)
        : to_("127.0.0.1", to), front_(open()), back_(open()), thread_([this] { run(); }) {}
    ~UdpForwarder() {
        running_ = false;
        thread_.join();
        librats::close_socket(front_);
        std::lock_guard<std::mutex> lock(mutex_);
        librats::close_socket(back_);
    }
    UdpForwarder(const UdpForwarder&) = delete;
    UdpForwarder& operator=(const UdpForwarder&) = delete;

    /// Where to dial through it.
    uint16_t port() const { return static_cast<uint16_t>(librats::get_bound_port(front_)); }
    /// Where the far end sees whoever dialed through it.
    librats::Address seen_at() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return librats::Address("127.0.0.1", static_cast<uint16_t>(librats::get_bound_port(back_)));
    }

    /// Go on from another port: the far end hears the dialer from somewhere new.
    void move() {
        std::lock_guard<std::mutex> lock(mutex_);
        librats::close_socket(back_);
        back_ = open();
    }
    /// Nothing passes on toward `to` / back from it.
    std::atomic<bool> drop_out{false};
    std::atomic<bool> drop_back{false};
    void cut() { drop_out = drop_back = true; }

private:
    static librats::socket_t open() {
        librats::socket_t s = librats::create_udp_socket(0, "127.0.0.1", librats::AddressFamily::IPv4,
                                                         librats::UdpPortMode::Exclusive);
        librats::set_socket_nonblocking(s);
        return s;
    }

    void run() {
        uint8_t buf[2048];
        librats::Address client, from;
        while (running_) {
            bool busy = false;
            std::ptrdiff_t n;
            while ((n = librats::recv_udp_from(front_, buf, sizeof buf, from)) >= 0) {
                busy = true;
                client = from;
                if (drop_out) continue;
                std::lock_guard<std::mutex> lock(mutex_);
                librats::send_udp_to(back_, buf, static_cast<size_t>(n), to_, librats::AddressFamily::IPv4);
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                while ((n = librats::recv_udp_from(back_, buf, sizeof buf, from)) >= 0) {
                    busy = true;
                    if (drop_back || client.port == 0) continue;
                    librats::send_udp_to(front_, buf, static_cast<size_t>(n), client,
                                         librats::AddressFamily::IPv4);
                }
            }
            if (!busy) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    const librats::Address  to_;
    const librats::socket_t front_;
    mutable std::mutex      mutex_;  ///< back_, which move() replaces
    librats::socket_t       back_;
    std::atomic<bool>       running_{true};
    std::thread             thread_;
};

} // namespace librats_test
