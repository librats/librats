#pragma once

// Driving datagram connections in virtual time, for the connection and the
// congestion tests.
//
// A UdpConnection never reads the clock and never touches a socket: it is handed
// datagrams and `now`, and it hands datagrams to its host. So two of them can be
// joined by a model of a path and run through hours of simulated time in
// milliseconds, deterministically. An End is one side — the host of one
// connection, a responder that accepts the first Initial it is sent the way the
// mux would. The path between two Ends is the test's (a Wire); Net is the plain
// one — a fixed delay and a hook — and Pair two Ends joined by it.

#include "librats/security/noise_security.h"
#include "librats/security/plaintext_security.h"
#include "librats/transport/udp_connection.h"
#include "librats/transport/udp_wire.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace udptest {

using namespace librats;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

/// What carries datagrams between Ends.
class Wire {
public:
    virtual ~Wire() = default;
    virtual void carry(const Address& from, const Address& to, const uint8_t* data, size_t len) = 0;
};

struct Message {
    MessageType       type;
    uint16_t          channel;
    std::string       payload;
    Clock::time_point deadline{};   ///< Frame::deadline
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
            conn->on_datagram(data, len, from, now);
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
                                    std::string(f.payload.begin(), f.payload.end()), f.deadline});
            return true;
        });
    }

    bool send(MessageType type, const std::string& payload, uint16_t channel = 0) {
        return conn && conn->send_message(FrameHeader{type, 0, channel}, ByteView(payload));
    }
    bool send(MessageType type, ByteView payload, uint16_t channel = 0) {
        return conn && conn->send_message(FrameHeader{type, 0, channel}, payload);
    }

    /// A live message, worth delivering until `deadline`; with a `tag`, its
    /// outcome is asked for. It leaves ahead of those of a higher `rank`.
    bool send_live(MessageType type, const std::string& payload, Clock::time_point deadline,
                   uint16_t channel = 0, uint64_t tag = 0, uint8_t rank = 0) {
        return conn && conn->send_live(FrameHeader{type, 0, channel}, ByteView(payload), deadline,
                                       tag, rank);
    }

    bool established() const { return conn && conn->established(); }

    // — UdpConnectionHost —
    uint8_t* datagram_buffer() override { return buf_.data(); }
    void send_datagram(const Address& to, size_t len) override {
        ++sent;
        wire_.carry(addr_, to, buf_.data(), len);
    }
    void connection_events(UdpConnection&, uint32_t e) override { events |= e; }
    void peer_moved(UdpConnection&) override { ++moves; }
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
    size_t   moves       = 0;   ///< peer_moved() calls

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

/// A path with a fixed one-way delay, a hook that may drop or rewrite any
/// datagram, and nothing else.
class Net final : public Wire {
public:
    explicit Net(Clock::duration delay) : delay_(delay) {}

    void carry(const Address& sender, const Address& to, const uint8_t* data, size_t len) override {
        Bytes bytes(data, data + len);
        const Address from = outside(sender);
        if (blackout || (hook && hook(bytes, from, to))) { ++dropped; return; }
        queue_.push_back({now_ + delay_, from, to, std::move(bytes)});
    }

    /// Put `end` behind a NAT that maps it to `external`: what it sends leaves
    /// from there, and only what is sent there reaches it. Called again, it is a
    /// rebinding — the old mapping is gone, and what is still sent to it is lost.
    void map(const End& end, const Address& external) { nat_[end.addr()] = external; }

    /// Put a datagram on the path as if `from` had just sent it.
    void inject(const Address& from, const Address& to, Bytes bytes) {
        queue_.push_back({now_ + delay_, from, to, std::move(bytes)});
    }

    void deliver_until(Clock::time_point now) {
        now_ = now;
        while (!queue_.empty() && queue_.front().arrive <= now) {
            Datagram d = std::move(queue_.front());
            queue_.pop_front();
            for (End* end : ends)
                if (outside(end->addr()) == d.to) end->receive(d.bytes.data(), d.bytes.size(), d.from, now);
        }
    }

    void set_now(Clock::time_point now) { now_ = now; }

    std::vector<End*> ends;
    /// Sees every datagram as it is sent; true drops it. May rewrite it.
    std::function<bool(Bytes& datagram, const Address& from, const Address& to)> hook;
    bool   blackout = false;
    size_t dropped  = 0;

private:
    struct Datagram {
        Clock::time_point arrive;
        Address           from, to;
        Bytes             bytes;
    };
    Address outside(const Address& inside) const {
        const auto it = nat_.find(inside);
        return it == nat_.end() ? inside : it->second;
    }

    Clock::duration      delay_;
    Clock::time_point    now_{};
    std::deque<Datagram> queue_;
    std::map<Address, Address> nat_;
};

/// The frames of a short packet sent under plaintext security, where the header
/// mask is zeros and nothing is sealed: what lets a hook see what a packet carries.
inline std::vector<udp::Frame> frames_of(const Bytes& d) {
    std::vector<udp::Frame> out;
    if (d.empty() || udp::is_long_header(d[0])) return out;
    const size_t header = udp::kShortHeaderSize + (d[0] & 0x03) + 1;
    udp::FrameReader r(d.data() + header, d.size() - header);
    udp::Frame f;
    while (r.next(f)) out.push_back(f);
    return out;
}

inline bool carries_stream(const Bytes& d, MessageType type) {
    for (const auto& f : frames_of(d))
        if (f.type == udp::kStream && f.stream.stream == static_cast<uint8_t>(type)) return true;
    return false;
}

inline bool is_short(const Bytes& d) { return !d.empty() && !udp::is_long_header(d[0]); }

inline bool is_handshake(const Bytes& d, udp::LongType type) {
    udp::LongPacket p;
    return !d.empty() && udp::is_long_header(d[0]) && udp::decode_long(d.data(), d.size(), p) && p.type == type;
}

struct Pair {
    explicit Pair(bool noise = true, Clock::duration one_way = 10ms, UdpConnectionConfig a_cfg = {},
                  UdpConnectionConfig b_cfg = {})
        : id_a(Identity::generate()), id_b(Identity::generate()),
          sec_a(noise ? std::unique_ptr<SecurityProvider>(new NoiseSecurity(id_a))
                      : std::unique_ptr<SecurityProvider>(new PlaintextSecurity(id_a))),
          sec_b(noise ? std::unique_ptr<SecurityProvider>(new NoiseSecurity(id_b))
                      : std::unique_ptr<SecurityProvider>(new PlaintextSecurity(id_b))),
          net(one_way), a(net, addr_a(), *sec_a, a_cfg), b(net, addr_b(), *sec_b, b_cfg) {
        net.ends = {&a, &b};
        a.listening = false;
    }

    void dial() { a.dial(b.addr(), 0x1000, now); }

    bool connect() {
        dial();
        return run_until([&] { return a.established() && b.established(); });
    }

    void step(Clock::duration dt = 1ms) {
        now += dt;
        net.deliver_until(now);
        a.tick(now);
        b.tick(now);
        a.read(now);
        b.read(now);
    }

    template <typename Pred>
    bool run_until(Pred pred, Clock::duration limit = 10s, Clock::duration dt = 1ms) {
        const auto end = now + limit;
        while (now < end) {
            if (pred()) return true;
            step(dt);
        }
        return pred();
    }

    void run(Clock::duration d, Clock::duration dt = 1ms) {
        const auto end = now + d;
        while (now < end) step(dt);
    }

    /// Queue on a, and let it send what it may.
    void send(MessageType type, const std::string& payload, uint16_t channel = 0) {
        ASSERT_TRUE(a.send(type, payload, channel));
        a.conn->flush(now);
    }

    Identity id_a, id_b;
    std::unique_ptr<SecurityProvider> sec_a, sec_b;
    Net net;
    End a, b;
    Clock::time_point now{};
};


} // namespace udptest
