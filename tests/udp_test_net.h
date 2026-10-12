#pragma once

// Driving datagram connections in virtual time, for the connection and the
// congestion tests.
//
// A UdpConnection never reads the clock and never touches a socket: it is handed
// datagrams and `now`, and it hands datagrams to its host. So two of them can be
// joined by a model of a path and run through hours of simulated time in
// milliseconds, deterministically. An End is one side — the host of one
// connection, a responder that accepts the first Initial it is sent the way the
// mux would. The path between two Ends is the test's (a Wire).

#include "librats/security/noise_security.h"
#include "librats/security/plaintext_security.h"
#include "librats/transport/udp_connection.h"
#include "librats/transport/udp_wire.h"

#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace udptest {

using namespace librats;
using Clock = std::chrono::steady_clock;

/// What carries datagrams between Ends.
class Wire {
public:
    virtual ~Wire() = default;
    virtual void carry(const Address& from, const Address& to, const uint8_t* data, size_t len) = 0;
};

struct Message {
    MessageType type;
    uint16_t    channel;
    std::string payload;
};

class End final : public UdpConnectionHost {
public:
    End(Wire& wire, Address addr, SecurityProvider& security, UdpConnectionConfig config = {})
        : wire_(wire), addr_(addr), security_(security), config_(config) {}

    const Address& addr() const noexcept { return addr_; }

    /// Dial `to` with connection id `cid` (even).
    void dial(const Address& to, udp::Cid cid, Clock::time_point now) {
        conn = UdpConnection::dial(*this, security_, to, cid, now, config_);
    }

    /// One datagram from the path.
    void receive(uint8_t* data, size_t len, const Address& from, Clock::time_point now) {
        ++received;
        if (conn) {
            udp::Cid dcid = 0;
            if (!udp::peek_dcid(data, len, dcid) || dcid != conn->local_cid()) return;
            if (conn->remote() != from) return;
            conn->on_datagram(data, len, now);
            return;
        }
        udp::LongPacket p;
        if (!listening || !udp::decode_long(data, len, p) || p.type != udp::LongType::Initial) return;
        conn = UdpConnection::accept(*this, security_, from, p, len, /*validated=*/false, now, config_);
        if (conn) conn->answer(now);
    }

    /// Service the connection's timers if any are due — what the mux does.
    void tick(Clock::time_point now) {
        if (!conn) return;
        const auto due = conn->next_deadline();
        if (due && *due <= now) conn->tick(now);
    }

    /// Hand over every complete message. Payloads are kept unless `count_only`.
    void read(Clock::time_point now) {
        if (!conn) return;
        conn->deliver(now, [&](const Frame& f) {
            ++messages_in;
            bytes_in += f.payload.size();
            if (!count_only)
                messages.push_back({f.header.type, f.header.channel,
                                    std::string(f.payload.begin(), f.payload.end())});
            return true;
        });
    }

    bool send(MessageType type, const std::string& payload, uint16_t channel = 0) {
        return conn && conn->send_message(FrameHeader{type, 0, channel}, ByteView(payload));
    }
    bool send(MessageType type, ByteView payload, uint16_t channel = 0) {
        return conn && conn->send_message(FrameHeader{type, 0, channel}, payload);
    }

    bool established() const { return conn && conn->established(); }

    // — UdpConnectionHost —
    uint8_t* datagram_buffer() override { return buf_.data(); }
    void send_datagram(const Address& to, size_t len) override {
        ++sent;
        wire_.carry(addr_, to, buf_.data(), len);
    }
    void connection_events(UdpConnection&, uint32_t e) override { events |= e; }
    void reset_token(udp::Cid cid, uint8_t* out) override {
        // Deterministic per id and per end, which is all a test needs of it.
        std::memset(out, 0x5A, udp::kResetTokenSize);
        std::memcpy(out, &cid, sizeof(cid));
        out[15] = static_cast<uint8_t>(addr_.port);
    }

    std::unique_ptr<UdpConnection> conn;
    std::vector<Message> messages;
    size_t   messages_in = 0;
    uint64_t bytes_in    = 0;
    bool     count_only  = false;
    bool     listening   = true;
    uint32_t events      = 0;
    size_t   sent        = 0;
    size_t   received    = 0;

private:
    Wire&               wire_;
    Address             addr_;
    SecurityProvider&   security_;
    UdpConnectionConfig config_;
    std::array<uint8_t, udp::kMaxDatagram> buf_{};
};

/// The two addresses every pair uses.
inline Address addr_a() { return Address{*IpAddress::parse("10.0.0.1"), 1111}; }
inline Address addr_b() { return Address{*IpAddress::parse("10.0.0.2"), 2222}; }

} // namespace udptest
