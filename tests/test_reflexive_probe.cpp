#include <gtest/gtest.h>
#include "test_paths.h"

#include "librats/core/socket.h"
#include "librats/nat/stun.h"
#include "librats/node/node.h"
#include "librats/node/reflexive_probe.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

using namespace librats;
using namespace std::chrono_literals;

namespace {

const Address kServer("192.0.2.1", 3478);

/// A STUN answer to `request` saying it came from `seen`.
Bytes answer(const Bytes& request, const Address& seen) {
    const std::optional<StunMessage> asked = StunMessage::deserialize(request);
    StunMessage reply;
    reply.type = StunMessageType::BindingSuccessResponse;
    reply.transaction_id = asked->transaction_id;
    reply.add_xor_mapped_address(StunMappedAddress(
        seen.ip.is_v4() ? StunAddressFamily::IPv4 : StunAddressFamily::IPv6, seen.ip.to_string(),
        seen.port));
    return reply.serialize();
}

/// A probe whose datagrams go to `server`, which may answer by calling back.
struct Rig {
    std::function<void(const Bytes& request)> server;
    std::atomic<int> sent{0};
    ReflexiveProbe probe{[this](const Address& to, Bytes datagram) {
        EXPECT_EQ(to, kServer);
        ++sent;
        if (server) server(datagram);
        return true;
    }};
};

} // namespace

TEST(ReflexiveProbe, LearnsWhereTheServerSeesTheSocket) {
    Rig rig;
    const Address seen("203.0.113.7", 51234);
    rig.server = [&](const Bytes& request) {
        rig.probe.on_datagram(answer(request, seen), kServer);
    };
    EXPECT_EQ(rig.probe.udp_endpoint(kServer, 2s), seen);
    EXPECT_EQ(rig.sent.load(), 1);
}

TEST(ReflexiveProbe, AsksAgainUntilAnswered) {
    Rig rig;
    const Address seen("203.0.113.7", 51234);
    rig.server = [&](const Bytes& request) {
        if (rig.sent.load() < 3) return;  // the first two are lost
        std::thread([&, reply = answer(request, seen)] { rig.probe.on_datagram(reply, kServer); })
            .detach();
    };
    EXPECT_EQ(rig.probe.udp_endpoint(kServer, 3s), seen);
    EXPECT_EQ(rig.sent.load(), 3);
}

TEST(ReflexiveProbe, TakesNoAnswerToAnotherRequestNorAnythingElse) {
    Rig rig;
    rig.server = [&](const Bytes&) {
        StunMessage other(StunMessageType::BindingRequest);  // another transaction id
        rig.probe.on_datagram(answer(other.serialize(), Address("203.0.113.66", 1)), kServer);
        const Bytes junk(40, 0x21);
        rig.probe.on_datagram(junk, kServer);
        rig.probe.on_datagram(ByteView(junk.data(), 3), kServer);
    };
    const auto started = std::chrono::steady_clock::now();
    EXPECT_FALSE(rig.probe.udp_endpoint(kServer, 600ms));
    EXPECT_GE(std::chrono::steady_clock::now() - started, 600ms);
    EXPECT_EQ(rig.sent.load(), 2);  // at 0 and at kRepeat
}

TEST(ReflexiveProbe, WithoutASocketThereIsNoAnswer) {
    ReflexiveProbe probe([](const Address&, Bytes) { return false; });
    const auto started = std::chrono::steady_clock::now();
    EXPECT_FALSE(probe.udp_endpoint(kServer, 5s));
    EXPECT_LT(std::chrono::steady_clock::now() - started, 1s);
}

// A node asks a STUN server from its shared datagram socket: on loopback, with
// no NAT, the server sees it at its own listen port.
TEST(ReflexiveProbe, ANodeAsksFromItsSharedSocket) {
    ASSERT_TRUE(init_socket_library());
    socket_t server = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(server));
    const Address at("127.0.0.1", static_cast<uint16_t>(get_bound_port(server)));
    std::atomic<bool> running{true};
    std::thread serving([&] {
        while (running) {
            Address from;
            const Bytes request = receive_udp_data(server, 1500, from, 50);
            if (request.empty()) continue;
            const Bytes reply = answer(request, from);
            send_udp_data(server, reply, from, AddressFamily::IPv4);
        }
    });

    // An IPv4 socket, and the dual-stack one a node binds by default.
    for (const char* bind : {"127.0.0.1", ""}) {
        NodeConfig config;
        config.bind_address = bind;
        config.protocol = librats_test::test_protocol();
        Node node(config);
        ASSERT_TRUE(node.start());
        auto* reflexive = node.services().get<ReflexiveAddressService>();
        ASSERT_NE(reflexive, nullptr);
        const std::optional<Address> seen = reflexive->udp_endpoint(at, 3s);
        ASSERT_TRUE(seen) << "bound to '" << bind << "'";
        EXPECT_EQ(*seen, Address("127.0.0.1", node.listen_port()));
        node.stop();
    }
    running = false;
    serving.join();
    close_socket(server);
}
