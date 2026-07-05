#include <gtest/gtest.h>

#include "core/address.h"
#include "core/host_endpoint.h"
#include "core/ip_address.h"
#include "core/socket.h"

#include <array>
#include <unordered_map>
#include <unordered_set>

using namespace librats;

namespace {
struct SocketLibrary {
    SocketLibrary() { init_socket_library(); }
};
const SocketLibrary g_socket_library;  // some platforms need winsock up for inet_ntop/pton
}  // namespace

// ── IpAddress: parse / to_string ─────────────────────────────────────────────

TEST(IpAddress, ParsesIPv4AndRoundTrips) {
    auto a = IpAddress::parse("192.168.1.42");
    ASSERT_TRUE(a);
    EXPECT_TRUE(a->is_v4());
    EXPECT_FALSE(a->is_v6());
    EXPECT_FALSE(a->is_unspecified());
    EXPECT_EQ(a->size(), 4u);
    EXPECT_EQ(a->to_string(), "192.168.1.42");
}

TEST(IpAddress, ParsesIPv6AndRoundTrips) {
    auto a = IpAddress::parse("2001:db8::dead:beef");
    ASSERT_TRUE(a);
    EXPECT_TRUE(a->is_v6());
    EXPECT_EQ(a->size(), 16u);
    EXPECT_EQ(a->to_string(), "2001:db8::dead:beef");
}

TEST(IpAddress, RejectsHostnamesAndGarbage) {
    EXPECT_FALSE(IpAddress::parse("router.bittorrent.com"));
    EXPECT_FALSE(IpAddress::parse("not-an-ip"));
    EXPECT_FALSE(IpAddress::parse(""));
    EXPECT_FALSE(IpAddress::parse("256.1.1.1"));
    EXPECT_FALSE(IpAddress::parse("1.2.3"));
}

TEST(IpAddress, DefaultIsUnspecified) {
    IpAddress a;
    EXPECT_TRUE(a.is_unspecified());
    EXPECT_TRUE(a.is_any());
    EXPECT_EQ(a.size(), 0u);
    EXPECT_TRUE(a.bytes().empty());
    EXPECT_EQ(a.to_string(), "");
}

// ── raw bytes ────────────────────────────────────────────────────────────────

TEST(IpAddress, FromBytesV4) {
    const std::array<uint8_t, 4> raw{10, 0, 0, 1};
    auto a = IpAddress::from_bytes(ByteView(raw.data(), raw.size()));
    ASSERT_TRUE(a);
    EXPECT_TRUE(a->is_v4());
    EXPECT_EQ(a->to_string(), "10.0.0.1");
    // bytes() reflects exactly the 4 stored octets
    ASSERT_EQ(a->bytes().size(), 4u);
    EXPECT_EQ(a->bytes().data()[0], 10);
    EXPECT_EQ(a->bytes().data()[3], 1);
}

TEST(IpAddress, FromBytesV6) {
    std::array<uint8_t, 16> raw{};
    raw[0] = 0x20; raw[1] = 0x01; raw[15] = 0x01;  // 2001::1
    auto a = IpAddress::from_bytes(ByteView(raw.data(), raw.size()));
    ASSERT_TRUE(a);
    EXPECT_TRUE(a->is_v6());
    EXPECT_EQ(a->to_string(), "2001::1");
}

TEST(IpAddress, FromBytesRejectsWrongLength) {
    const std::array<uint8_t, 5> five{};
    EXPECT_FALSE(IpAddress::from_bytes(ByteView(five.data(), five.size())));
    EXPECT_FALSE(IpAddress::from_bytes(ByteView(nullptr, 0)));
}

TEST(IpAddress, ParseThenBytesRoundTrip) {
    auto a = IpAddress::parse("172.16.5.9");
    ASSERT_TRUE(a);
    auto b = IpAddress::from_bytes(a->bytes());
    ASSERT_TRUE(b);
    EXPECT_EQ(*a, *b);
}

// ── is_any (wildcard) ────────────────────────────────────────────────────────

TEST(IpAddress, IsAnyDetectsWildcards) {
    EXPECT_TRUE(IpAddress::parse("0.0.0.0")->is_any());
    EXPECT_TRUE(IpAddress::parse("::")->is_any());
    EXPECT_FALSE(IpAddress::parse("0.0.0.1")->is_any());
    EXPECT_FALSE(IpAddress::parse("127.0.0.1")->is_any());
    // an all-zero wildcard is still a specified (v4/v6) address, unlike the default
    EXPECT_FALSE(IpAddress::parse("0.0.0.0")->is_unspecified());
}

// ── sockaddr conversion ──────────────────────────────────────────────────────

TEST(IpAddress, SockaddrRoundTripV4) {
    auto a = IpAddress::parse("203.0.113.7");
    ASSERT_TRUE(a);
    sockaddr_storage ss{};
    const size_t len = a->to_sockaddr(reinterpret_cast<sockaddr*>(&ss), 8080);
    EXPECT_EQ(len, sizeof(sockaddr_in));
    EXPECT_EQ(ss.ss_family, AF_INET);
    auto back = IpAddress::from_sockaddr(reinterpret_cast<sockaddr*>(&ss));
    ASSERT_TRUE(back);
    EXPECT_EQ(*back, *a);
}

TEST(IpAddress, SockaddrRoundTripV6) {
    auto a = IpAddress::parse("2001:db8::1");
    ASSERT_TRUE(a);
    sockaddr_storage ss{};
    const size_t len = a->to_sockaddr(reinterpret_cast<sockaddr*>(&ss), 9000);
    EXPECT_EQ(len, sizeof(sockaddr_in6));
    EXPECT_EQ(ss.ss_family, AF_INET6);
    auto back = IpAddress::from_sockaddr(reinterpret_cast<sockaddr*>(&ss));
    ASSERT_TRUE(back);
    EXPECT_EQ(*back, *a);
}

TEST(IpAddress, FromSockaddrUnwrapsV4Mapped) {
    // ::ffff:198.51.100.9 must decode as a native IPv4 so a dual-stack socket's
    // view of a v4 peer compares equal to a plain v4 address.
    sockaddr_in6 in6{};
    in6.sin6_family = AF_INET6;
    ASSERT_EQ(inet_pton(AF_INET6, "::ffff:198.51.100.9", &in6.sin6_addr), 1);
    auto a = IpAddress::from_sockaddr(reinterpret_cast<sockaddr*>(&in6));
    ASSERT_TRUE(a);
    EXPECT_TRUE(a->is_v4());
    EXPECT_EQ(a->to_string(), "198.51.100.9");
    EXPECT_EQ(*a, *IpAddress::parse("198.51.100.9"));
}

TEST(IpAddress, UnspecifiedToSockaddrWritesNothing) {
    IpAddress a;
    sockaddr_storage ss{};
    EXPECT_EQ(a.to_sockaddr(reinterpret_cast<sockaddr*>(&ss), 1234), 0u);
}

// ── equality / ordering / hashing ────────────────────────────────────────────

TEST(IpAddress, EqualityAndOrdering) {
    auto v4 = *IpAddress::parse("1.2.3.4");
    auto v4b = *IpAddress::parse("1.2.3.4");
    auto v6 = *IpAddress::parse("::1");
    EXPECT_EQ(v4, v4b);
    EXPECT_NE(v4, v6);
    // family orders before bytes: every v4 sorts before every v6
    EXPECT_LT(v4, v6);
}

TEST(IpAddress, UsableAsHashKey) {
    std::unordered_set<IpAddress> set;
    set.insert(*IpAddress::parse("1.1.1.1"));
    set.insert(*IpAddress::parse("1.1.1.1"));  // duplicate
    set.insert(*IpAddress::parse("2606:4700::1111"));
    EXPECT_EQ(set.size(), 2u);
    EXPECT_TRUE(set.count(*IpAddress::parse("1.1.1.1")));
}

// ── Address (endpoint) ───────────────────────────────────────────────────────

TEST(AddressEndpoint, ConstructFromLiteral) {
    Address a{"1.2.3.4", 8080};
    EXPECT_EQ(a.ip.to_string(), "1.2.3.4");
    EXPECT_EQ(a.port, 8080);
    EXPECT_TRUE(a.is_valid());
}

TEST(AddressEndpoint, ParseRoundTrip) {
    for (const char* s : {"127.0.0.1:8080", "[2001:db8::1]:443", "[::1]:9000"}) {
        auto a = Address::parse(s);
        ASSERT_TRUE(a) << s;
        EXPECT_EQ(a->to_string(), s);
    }
}

TEST(AddressEndpoint, ParseRejectsBareIPv6AndHostname) {
    EXPECT_FALSE(Address::parse("2001:db8::1:443"));   // bare v6: ambiguous colons
    EXPECT_FALSE(Address::parse("example.com:80"));    // hostname: not numeric
    EXPECT_FALSE(Address::parse("1.2.3.4"));           // no port
    EXPECT_FALSE(Address::parse("1.2.3.4:0"));         // zero port
}

TEST(AddressEndpoint, ValidityAndHashKey) {
    EXPECT_FALSE(Address{}.is_valid());                 // unspecified ip
    EXPECT_FALSE((Address{"1.2.3.4", 0}).is_valid());   // zero port

    std::unordered_map<Address, int> m;
    m[Address{"1.2.3.4", 80}] = 1;
    m[Address{"1.2.3.4", 80}] = 2;   // same key
    m[Address{"1.2.3.4", 81}] = 3;   // different port → different key
    EXPECT_EQ(m.size(), 2u);
    EXPECT_EQ((m[Address{"1.2.3.4", 80}]), 2);
}

// ── HostEndpoint (unresolved spec) ───────────────────────────────────────────

TEST(HostEndpointSpec, ParsesHostnameAndLiteral) {
    auto h = HostEndpoint::parse("router.bittorrent.com:6881");
    ASSERT_TRUE(h);
    EXPECT_EQ(h->host, "router.bittorrent.com");
    EXPECT_EQ(h->port, 6881);
    EXPECT_EQ(h->to_string(), "router.bittorrent.com:6881");

    auto v6 = HostEndpoint::parse("[2001:db8::1]:25401");
    ASSERT_TRUE(v6);
    EXPECT_EQ(v6->host, "2001:db8::1");
    EXPECT_EQ(v6->port, 25401);
    EXPECT_EQ(v6->to_string(), "[2001:db8::1]:25401");  // literal host re-bracketed
}

TEST(HostEndpointSpec, RejectsMalformed) {
    EXPECT_FALSE(HostEndpoint::parse("host-without-port"));
    EXPECT_FALSE(HostEndpoint::parse("host:0"));
    EXPECT_FALSE(HostEndpoint::parse("host:99999"));
    EXPECT_FALSE(HostEndpoint::parse("2001:db8::1:6881"));  // bare v6: ambiguous
}
