#include <gtest/gtest.h>

#include "core/socket.h"  // init_socket_library (winsock needs WSAStartup before resolving)
#include "dht/dht.h"
#include "util/network_utils.h"

using namespace librats;

namespace {
// Hostname resolution needs the socket library up (WSAStartup on Windows). In the real
// library UdpTransport does this at DhtClient::start(), before bootstrap() ever resolves;
// in this unit test we bring it up ourselves so the resolving cases actually exercise.
struct SocketLibrary {
    SocketLibrary() { init_socket_library(); }
};
const SocketLibrary g_socket_library;
}  // namespace

// resolve_bootstrap_nodes() must hand the DHT engine only numeric IPs of the right
// family. The engine matches a reply's source address verbatim against the address it
// queried (anti-spoofing), so a seed left as a hostname would have every reply dropped
// and the node would never bootstrap. This regressed in "split dht implementation",
// where the unconditional anti-spoofing met unresolved hostname seeds.

TEST(DhtBootstrap, KeepsNumericIPv4ForIPv4Family) {
    const std::vector<Address> in{Address("1.2.3.4", 6881)};
    const auto out = resolve_bootstrap_nodes(in, /*ipv6=*/false);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], Address("1.2.3.4", 6881));  // passed through unchanged
}

TEST(DhtBootstrap, KeepsNumericIPv6ForIPv6Family) {
    const std::vector<Address> in{Address("2001:db8::1", 6881)};
    const auto out = resolve_bootstrap_nodes(in, /*ipv6=*/true);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0], Address("2001:db8::1", 6881));
}

TEST(DhtBootstrap, DropsWrongFamilyLiterals) {
    const std::vector<Address> in{Address("1.2.3.4", 6881), Address("2001:db8::1", 6881)};

    const auto v4 = resolve_bootstrap_nodes(in, /*ipv6=*/false);
    ASSERT_EQ(v4.size(), 1u);
    EXPECT_EQ(v4[0].ip, "1.2.3.4");  // the IPv6 literal is dropped for an IPv4 node

    const auto v6 = resolve_bootstrap_nodes(in, /*ipv6=*/true);
    ASSERT_EQ(v6.size(), 1u);
    EXPECT_EQ(v6[0].ip, "2001:db8::1");  // and vice versa
}

TEST(DhtBootstrap, ResolvesHostnameToNumericIPv4) {
    // localhost resolves from the hosts file on every supported platform, so this is
    // deterministic and offline. The point: the hostname must NOT pass through verbatim.
    const std::vector<Address> in{Address("localhost", 6881)};
    const auto out = resolve_bootstrap_nodes(in, /*ipv6=*/false);
    if (out.empty()) GTEST_SKIP() << "localhost did not resolve to IPv4 in this environment";

    ASSERT_EQ(out.size(), 1u);
    EXPECT_TRUE(network_utils::is_valid_ipv4(out[0].ip)) << "got: " << out[0].ip;
    EXPECT_NE(out[0].ip, "localhost");  // the regression: a hostname leaking through
    EXPECT_EQ(out[0].port, 6881);       // port preserved
}

TEST(DhtBootstrap, DropsEmptyHostAndZeroPort) {
    const std::vector<Address> in{Address("", 6881), Address("1.2.3.4", 0)};
    EXPECT_TRUE(resolve_bootstrap_nodes(in, /*ipv6=*/false).empty());
}

TEST(DhtBootstrap, DropsUnresolvableHostname) {
    const std::vector<Address> in{Address("nonexistent.invalid.", 6881)};
    // .invalid is reserved (RFC 2606) and must never resolve — it is filtered out, not
    // forwarded as an unmatchable hostname seed.
    EXPECT_TRUE(resolve_bootstrap_nodes(in, /*ipv6=*/false).empty());
}
