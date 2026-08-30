#include <gtest/gtest.h>

#include "librats/mdns/mdns.h"

#include <set>
#include <string>

using namespace librats;

// The host name an mDNS client announces has to be unique on the network, because it
// is what a peer resolves to get an address. It used to be the system's own host name,
// which is not unique where it matters most: Android reports "localhost" for every
// device, so every Android node on a LAN claimed "localhost.local." and a resolver
// asking for it got whichever answered first — pointing the dialer at the wrong phone.
//
// These are pure-accessor tests: no socket is opened and nothing is announced, so they
// run identically on every platform (including Apple, where MdnsClient is not the
// backend MdnsDiscovery uses).

TEST(MdnsHostNameTest, DiffersPerInstance) {
    MdnsClient first("rats-aaaaaaaa", 45001);
    MdnsClient second("rats-bbbbbbbb", 45002);

    EXPECT_NE(first.host_name(), second.host_name());
    EXPECT_EQ(first.host_name(), "rats-aaaaaaaa.local.");
    EXPECT_EQ(second.host_name(), "rats-bbbbbbbb.local.");
}

// The regression proper: two nodes on two devices whose system host names are both
// "localhost" must still announce distinct names.
TEST(MdnsHostNameTest, DoesNotFallBackToTheSystemNameWhenNamed) {
    std::set<std::string> names;
    for (const char* instance : {"rats-11111111", "rats-22222222", "rats-33333333"}) {
        names.insert(MdnsClient(instance, 45003).host_name());
    }
    EXPECT_EQ(names.size(), 3u) << "instances collapsed onto one host name";
    EXPECT_EQ(names.count("localhost.local."), 0u);
}

// An unnamed client has nothing to name itself after and falls back to the system, but
// must still produce something syntactically usable.
TEST(MdnsHostNameTest, StaysAValidNameWithoutAnInstance) {
    const std::string name = MdnsClient().host_name();

    ASSERT_FALSE(name.empty());
    EXPECT_NE(name, ".local.");
    EXPECT_EQ(name.rfind(".local."), name.size() - 7) << name;
}

TEST(MdnsHostNameTest, SanitisesAndBoundsTheLabel) {
    // Spaces and dots inside a label would split it or make it illegal.
    EXPECT_EQ(MdnsClient("my node.v2", 45004).host_name(), "my-node-v2.local.");

    // A label stops at 63 octets, and truncating must not leave a trailing hyphen.
    const std::string long_name = MdnsClient(std::string(80, 'a'), 45005).host_name();
    EXPECT_EQ(long_name, std::string(63, 'a') + ".local.");

    const std::string hyphenated = MdnsClient(std::string(62, 'b') + "-cd", 45006).host_name();
    EXPECT_EQ(hyphenated, std::string(62, 'b') + ".local.") << hyphenated;
}
