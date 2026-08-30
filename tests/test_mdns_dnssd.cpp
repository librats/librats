#include <gtest/gtest.h>

#include "librats/mdns/mdns_dnssd.h"

#include <chrono>
#include <mutex>
#include <set>
#include <string>
#include <thread>

using namespace librats;
using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(10ms);
    }
    return pred();
}

} // namespace

// Registration is asserted rather than merely attempted: DNSServiceRegister talks to
// mDNSResponder over a local UNIX socket, and the daemon confirms the registration
// without any packet leaving the machine. So this holds on a sandboxed or unplugged
// host — the one thing it does need is mDNSResponder itself, which is present on every
// Apple platform. Browsing is the part that depends on the network (and, since
// macOS 15, on local-network consent), which is why nothing here asserts a discovery.
TEST(DnssdMdnsTest, RegistersWithMdnsResponder) {
    DnssdMdnsClient client("rats-test-register", 45301);

    ASSERT_TRUE(client.start());
    EXPECT_TRUE(client.is_running());

    EXPECT_TRUE(client.announce_service("rats-test-register", 45301));
    EXPECT_TRUE(wait_for([&] { return client.is_announcing(); }, 5s));

    client.stop();
    EXPECT_FALSE(client.is_running());
    EXPECT_FALSE(client.is_announcing());
}

// Browsing must not be assumed to find anything, but it must start and tear down
// without stalling — the worker thread has to notice the stop while blocked in select().
TEST(DnssdMdnsTest, BrowseStartsAndStopsPromptly) {
    DnssdMdnsClient client("rats-test-browse", 45302);
    ASSERT_TRUE(client.start());
    EXPECT_TRUE(client.start_discovery());
    EXPECT_TRUE(wait_for([&] { return client.is_discovering(); }, 5s));

    const auto began = std::chrono::steady_clock::now();
    client.stop();
    const auto took = std::chrono::steady_clock::now() - began;

    EXPECT_FALSE(client.is_discovering());
    // The select() timeout is 1s; the wakeup pipe is what makes this immediate. If the
    // pipe were not in the read set, stop() would take up to a second and this would
    // catch it.
    EXPECT_LT(took, 500ms);
}

// A second cycle on the same object catches teardown that leaves a DNSServiceRef
// dangling — the failure mode of deallocating in the wrong order or twice.
TEST(DnssdMdnsTest, SurvivesRestart) {
    DnssdMdnsClient client("rats-test-restart", 45303);

    for (int cycle = 0; cycle < 2; ++cycle) {
        ASSERT_TRUE(client.start()) << "cycle " << cycle;
        client.announce_service("rats-test-restart", 45303);
        client.start_discovery();
        EXPECT_TRUE(wait_for([&] { return client.is_announcing(); }, 5s)) << "cycle " << cycle;
        client.stop();
        EXPECT_FALSE(client.is_running()) << "cycle " << cycle;
    }
}

// Stopping must actually withdraw the registration, not just stop our own browsing.
// A leaked registration is worse than no mDNS: mDNSResponder keeps handing peers an
// address whose node is gone, so every one of them dials a dead port and waits out a
// timeout. Nothing in this process would notice, which is why it is asserted from a
// second client's point of view rather than from the advertiser's own state.
//
// The browse half is a separate client on the same host, which works because this
// backend reports every instance mDNSResponder knows about, including local ones.
TEST(DnssdMdnsTest, DeregistersOnStop) {
    const std::string label = "rats-test-deregister";

    std::mutex             mutex;
    std::set<std::string>  seen;
    const auto collect = [&](const MdnsService& service, bool) {
        std::lock_guard<std::mutex> lock(mutex);
        seen.insert(service.service_name);
    };
    const auto saw_label = [&] {
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& name : seen) {
            if (name.find(label) != std::string::npos) return true;
        }
        return false;
    };

    DnssdMdnsClient advertiser(label, 45305);
    ASSERT_TRUE(advertiser.start());
    ASSERT_TRUE(advertiser.announce_service(label, 45305));
    ASSERT_TRUE(wait_for([&] { return advertiser.is_announcing(); }, 5s));

    {
        DnssdMdnsClient watcher("rats-test-watcher", 45306);
        watcher.set_service_callback(collect);
        ASSERT_TRUE(watcher.start());
        ASSERT_TRUE(watcher.start_discovery());
        EXPECT_TRUE(wait_for(saw_label, 15s)) << "the advertised service was never seen";
        watcher.stop();
    }

    advertiser.stop();
    {
        std::lock_guard<std::mutex> lock(mutex);
        seen.clear();
    }

    // A fresh browse, so this is what mDNSResponder currently knows rather than what
    // the previous watcher had cached.
    DnssdMdnsClient after("rats-test-after", 45307);
    after.set_service_callback(collect);
    ASSERT_TRUE(after.start());
    ASSERT_TRUE(after.start_discovery());
    std::this_thread::sleep_for(4s);
    EXPECT_FALSE(saw_label()) << "the service is still advertised after stop()";
    after.stop();
}

// stop() without start(), and stop() twice, are both no-ops rather than crashes: the
// subsystem's destructor calls stop() after MdnsDiscovery::stop() already did.
TEST(DnssdMdnsTest, StopIsIdempotent) {
    DnssdMdnsClient client("rats-test-idempotent", 45304);

    client.stop();
    EXPECT_FALSE(client.is_running());

    ASSERT_TRUE(client.start());
    client.stop();
    client.stop();
    EXPECT_FALSE(client.is_running());
}
