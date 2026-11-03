#include <gtest/gtest.h>
#include "test_paths.h"

#include "librats/node/host_events.h"
#include "librats/node/node.h"
#include "librats/node/node_context.h"
#include "librats/subsystems/dht_discovery.h"
#include "librats/nat/stun.h"
#include "librats/core/socket.h"
#include "librats/util/fs.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace librats;
using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return pred();
}

// A loopback STUN server that always reports a fixed (public) reflexive address,
// so we can exercise the STUN → DHT node-id seeding path entirely offline.
class FixedStunServer {
public:
    explicit FixedStunServer(std::string public_ip, uint16_t public_port = 41234)
        : public_ip_(std::move(public_ip)), public_port_(public_port) {}
    ~FixedStunServer() { stop(); }

    bool start() {
        if (!init_socket_library()) return false;
        socket_ = create_udp_socket(0);
        if (!is_valid_socket(socket_)) return false;
        port_ = get_bound_port(socket_);
        running_ = true;
        thread_ = std::thread(&FixedStunServer::run, this);
        return true;
    }

    void stop() {
        running_ = false;
        // Join first — run() polls with a 100 ms timeout and exits on its own. Closing
        // the fd while it sits in recvfrom() would race with it.
        if (thread_.joinable()) thread_.join();
        if (is_valid_socket(socket_)) { close_socket(socket_); socket_ = RATS_INVALID_SOCKET; }
    }

    uint16_t port() const { return static_cast<uint16_t>(port_); }

private:
    void run() {
        while (running_) {
            Address sender;
            auto data = receive_udp_data(socket_, 1500, sender, 100);
            if (data.empty()) continue;
            auto req = StunMessage::deserialize(data);
            if (!req || !req->is_request()) continue;

            StunMessage resp;
            resp.type = StunMessageType::BindingSuccessResponse;
            resp.transaction_id = req->transaction_id;
            resp.add_xor_mapped_address(StunMappedAddress(StunAddressFamily::IPv4, public_ip_, public_port_));
            resp.add_software("FixedStunServer/1.0");
            auto out = resp.serialize();
            send_udp_data(socket_, out, sender.ip.to_string(), sender.port);
        }
    }

    std::string       public_ip_;
    uint16_t          public_port_;
    std::atomic<bool> running_{false};
    socket_t          socket_ = RATS_INVALID_SOCKET;
    int               port_ = 0;
    std::thread       thread_;
};

// Tells the node, once started, that the router forwards `port` to it — what
// PortMappingService says when UPnP or NAT-PMP maps it.
class FakePortMapping final : public Subsystem {
public:
    explicit FakePortMapping(uint16_t port) : port_(port) {}
    void attach(NodeContext& ctx) override { events_ = &ctx.events; }
    void start() override { events_->emit(PortMapped{PortMapProtocol::UDP, "1.2.3.4", port_}); }
    void stop() override {}

private:
    uint16_t  port_;
    EventBus* events_ = nullptr;
};

// A UDP port nothing answers on, counting the dials' Initials (padded to 1220
// bytes) that arrive.
class SilentPort {
public:
    SilentPort() {
        init_socket_library();
        socket_ = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
        port_ = static_cast<uint16_t>(get_bound_port(socket_));
        thread_ = std::thread([this] {
            while (running_) {
                Address from;
                if (receive_udp_data(socket_, 1500, from, 50).size() >= 1200) ++initials_;
            }
        });
    }
    ~SilentPort() {
        running_ = false;
        thread_.join();
        close_socket(socket_);
    }
    uint16_t port() const { return port_; }
    int initials() const { return initials_.load(); }

private:
    socket_t          socket_ = RATS_INVALID_SOCKET;
    uint16_t          port_ = 0;
    std::atomic<bool> running_{true};
    std::atomic<int>  initials_{0};
    std::thread       thread_;
};

NodeConfig listening_config() {
    NodeConfig c; c.bind_address = "127.0.0.1"; c.security = NodeConfig::Security::Noise; c.protocol = librats_test::test_protocol(); return c;
}

DhtDiscovery::Config disc_config(const std::vector<HostEndpoint>& bootstrap) {
    DhtDiscovery::Config c;
    c.discovery_key = "librats-test-net";
    c.bind_address = "127.0.0.1";
    c.bootstrap_nodes = bootstrap;
    c.search_interval = 500ms;
    c.announce_interval = 1000ms;
    c.discover_external_ip = false;  // offline: no public STUN
    return c;
}

bool ipv6_loopback_available() {
    // Winsock must be up before any socket() call; this probe can run before the
    // first Node::start() (which is what otherwise initialises it), so do it here —
    // otherwise the probe always fails on Windows and the dual-stack tests skip on
    // hosts that actually have IPv6 loopback.
    if (!init_socket_library()) return false;
    socket_t s = create_udp_socket(0, "::1", AddressFamily::IPv6);
    if (!is_valid_socket(s)) return false;
    close_socket(s);
    return true;
}

} // namespace

// The discovery hash is a deterministic function of the key.
TEST(DhtDiscoveryTest, HashIsDeterministicPerKey) {
    EXPECT_EQ(DhtDiscovery::hash_for_key("app-a"), DhtDiscovery::hash_for_key("app-a"));
    EXPECT_NE(DhtDiscovery::hash_for_key("app-a"), DhtDiscovery::hash_for_key("app-b"));
}

// A peer found is dialed at once, then again as found again — no oftener than
// every in its first stretch, and after it no oftener than slow.
TEST(DhtDiscoveryTest, RedialsWhatItFindsForAWhile) {
    using Dial = DhtDiscovery::Redials::Dial;
    using Clock = DhtDiscovery::Redials::Clock;
    DhtDiscovery::Redials redials(5s, 20s, 25s);
    const Address a("203.0.113.1", 4000);
    const Address b("203.0.113.2", 4000);
    const Clock::time_point t0{};

    EXPECT_EQ(redials.found(a, t0), Dial::First);
    EXPECT_EQ(redials.found(a, t0 + 1s), Dial::None);   // dialed just now
    EXPECT_EQ(redials.found(b, t0 + 1s), Dial::First);  // each its own
    EXPECT_EQ(redials.found(a, t0 + 5s), Dial::Again);
    EXPECT_EQ(redials.found(a, t0 + 9s), Dial::None);
    EXPECT_EQ(redials.found(a, t0 + 10s), Dial::Again);
    EXPECT_EQ(redials.found(a, t0 + 21s), Dial::None);  // past its first stretch: slow

    redials.forget_older_than(t0 + 15s);  // b, last found at 1 s
    EXPECT_EQ(redials.size(), 1u);
    EXPECT_EQ(redials.found(b, t0 + 30s), Dial::First);
    EXPECT_EQ(redials.found(a, t0 + 30s), Dial::None);   // 20 s after the last
    EXPECT_EQ(redials.found(a, t0 + 35s), Dial::Again);  // 25 s after
}

// In its first stretch a peer found is punched on its own time, every `every`,
// whether the DHT hands it out again or not (that is once a round, 30 s: two
// behind NATs punching that seldom may never overlap).
TEST(DhtDiscoveryTest, RedialsPunchOnTheirOwnTimeInTheFirstStretch) {
    using Dial = DhtDiscovery::Redials::Dial;
    using Clock = DhtDiscovery::Redials::Clock;
    using Addresses = std::vector<Address>;
    DhtDiscovery::Redials redials(5s, 20s, 25s);
    const Address a("203.0.113.1", 4000);
    const Clock::time_point t0{};

    EXPECT_FALSE(redials.next_due().has_value());  // none found
    EXPECT_EQ(redials.found(a, t0), Dial::First);
    EXPECT_EQ(redials.next_due(), t0 + 5s);
    EXPECT_TRUE(redials.due(t0 + 4s).empty());
    EXPECT_EQ(redials.due(t0 + 5s), Addresses{a});
    EXPECT_TRUE(redials.due(t0 + 5s).empty());          // punched just now
    EXPECT_EQ(redials.found(a, t0 + 7s), Dial::None);   // found again: punched at 5 s
    EXPECT_EQ(redials.next_due(), t0 + 10s);
    EXPECT_EQ(redials.due(t0 + 12s), Addresses{a});     // a late wake: the next 5 s on
    EXPECT_EQ(redials.next_due(), t0 + 17s);
    EXPECT_EQ(redials.due(t0 + 17s), Addresses{a});
    EXPECT_FALSE(redials.next_due().has_value());       // 22 s is past the stretch
    EXPECT_TRUE(redials.due(t0 + 22s).empty());

    // Found connected: nothing left to punch.
    const Address b("203.0.113.2", 4000);
    EXPECT_EQ(redials.found(b, t0 + 30s), Dial::First);
    EXPECT_EQ(redials.next_due(), t0 + 35s);
    redials.connected(b);
    EXPECT_FALSE(redials.next_due().has_value());
    EXPECT_TRUE(redials.due(t0 + 35s).empty());
}

// A peer found while it was away — the DHT keeps its announce half an hour —
// and back later at the same address is still punched, once a round for as
// long as it is found: its own punches, every few seconds, then land while
// ours keep our NAT open to it. (Left at its first two minutes, it was never
// dialed again, and two behind NATs never met.)
TEST(DhtDiscoveryTest, RedialsAPeerFoundForAsLongAsItIsFound) {
    using Dial = DhtDiscovery::Redials::Dial;
    using Clock = DhtDiscovery::Redials::Clock;
    DhtDiscovery::Redials redials(5s, 20s, 25s);
    const Address a("203.0.113.1", 4000);
    const Clock::time_point t0{};

    EXPECT_EQ(redials.found(a, t0), Dial::First);
    for (auto at = t0 + 5s; at <= t0 + 20s; at += 5s) EXPECT_EQ(redials.due(at).size(), 1u);
    int punched = 0;
    for (auto at = t0 + 30s; at <= t0 + 30min; at += 30s) {  // a search round
        if (redials.found(a, at) == Dial::Again) ++punched;
        redials.forget_older_than(at - 10min);
    }
    EXPECT_EQ(punched, 59);  // every round from 30 s to 30 min
    EXPECT_EQ(redials.size(), 1u);
}

// A peer found connected, whose link then goes, is dialed for anew however long
// ago it was first found: two that stay up find each other again.
TEST(DhtDiscoveryTest, RedialsAPeerFoundConnectedOnceItsLinkIsGone) {
    using Dial = DhtDiscovery::Redials::Dial;
    using Clock = DhtDiscovery::Redials::Clock;
    DhtDiscovery::Redials redials(5s, 20s, 25s);
    const Address a("203.0.113.1", 4000);
    const Clock::time_point t0{};

    EXPECT_EQ(redials.found(a, t0), Dial::First);
    EXPECT_EQ(redials.found(a, t0 + 3s), Dial::None);
    redials.connected(a);
    EXPECT_EQ(redials.found(a, t0 + 600s), Dial::First);
    EXPECT_EQ(redials.found(a, t0 + 605s), Dial::Again);
}

// The adapter brings a DhtClient up on a real UDP port and tears down cleanly.
TEST(DhtDiscoveryTest, StartsAndStopsCleanly) {
    Node node(listening_config());
    auto disc = std::make_unique<DhtDiscovery>(disc_config({}));  // no bootstrap (offline)
    DhtDiscovery* d = disc.get();
    node.add_subsystem(std::move(disc));

    ASSERT_TRUE(node.start());
    EXPECT_TRUE(wait_for([&] { return d->is_running() && d->dht_port() != 0; }, 5s));
    node.stop();
    EXPECT_FALSE(d->is_running());
}

// STUN seeds the DHT node id: a successful binding response with a public address
// is fed to the DHT (BEP 42), so external_address() reflects it.
TEST(DhtDiscoveryTest, SeedsNodeIdFromStun) {
    FixedStunServer stun("1.2.3.4");
    ASSERT_TRUE(stun.start());

    Node node(listening_config());
    auto cfg = disc_config({});  // offline, no bootstrap
    cfg.discover_external_ip = true;
    cfg.stun_servers = { HostEndpoint("127.0.0.1", stun.port()) };
    cfg.stun_timeout = 2000ms;
    auto disc = std::make_unique<DhtDiscovery>(cfg);
    DhtDiscovery* d = disc.get();
    node.add_subsystem(std::move(disc));

    ASSERT_TRUE(node.start());
    EXPECT_TRUE(wait_for([&] { return d->external_address() == "1.2.3.4"; }, 10s))
        << "external addr: '" << d->external_address() << "'";

    node.stop();
    stun.stop();
}

// When no STUN server answers, discovery still starts/stops cleanly and simply
// leaves the node id random (the in-DHT voting fallback is unavailable offline).
TEST(DhtDiscoveryTest, StartsCleanlyWhenStunUnreachable) {
    Node node(listening_config());
    auto cfg = disc_config({});
    cfg.discover_external_ip = true;
    cfg.stun_servers = { HostEndpoint("127.0.0.1", 1) };  // nothing is listening there
    cfg.stun_timeout = 300ms;
    auto disc = std::make_unique<DhtDiscovery>(cfg);
    DhtDiscovery* d = disc.get();
    node.add_subsystem(std::move(disc));

    ASSERT_TRUE(node.start());
    EXPECT_TRUE(wait_for([&] { return d->is_running() && d->dht_port() != 0; }, 5s));
    EXPECT_EQ(d->external_address(), "");
    node.stop();
    EXPECT_FALSE(d->is_running());
}

// Two nodes bootstrap their DHTs off each other on loopback, announce the same
// discovery hash, find each other's TCP port and form an encrypted peer link —
// all offline. (DHT convergence is timing-dependent; generous timeout.)
TEST(DhtDiscoveryTest, TwoNodesDiscoverViaDht) {
    Node a(listening_config());
    auto disc_a = std::make_unique<DhtDiscovery>(disc_config({}));  // seed: no bootstrap
    DhtDiscovery* da = disc_a.get();
    a.add_subsystem(std::move(disc_a));
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(wait_for([&] { return da->dht_port() != 0; }, 5s));

    // b bootstraps from a's DHT node.
    Node b(listening_config());
    std::vector<HostEndpoint> bootstrap{ HostEndpoint("127.0.0.1", da->dht_port()) };
    b.add_subsystem(std::make_unique<DhtDiscovery>(disc_config(bootstrap)));
    ASSERT_TRUE(b.start());

    EXPECT_TRUE(wait_for([&] { return a.peer_count() >= 1 && b.peer_count() >= 1; }, 30s))
        << "discovered: a=" << a.peer_count() << " b=" << b.peer_count();

    b.stop();
    a.stop();
}

// Keys given are the hashes, each once, in place of the discovery key; set as
// the node runs, they replace those before.
TEST(DhtDiscoveryTest, KeysGivenAreTheHashes) {
    Node node(listening_config());
    auto cfg = disc_config({});
    cfg.keys = {"one", "two"};
    auto disc = std::make_unique<DhtDiscovery>(cfg);
    DhtDiscovery* d = disc.get();
    node.add_subsystem(std::move(disc));
    EXPECT_EQ(d->discovery_hashes(),
              (std::vector<InfoHash>{DhtDiscovery::hash_for_key("one"), DhtDiscovery::hash_for_key("two")}));
    EXPECT_EQ(d->discovery_hash(), DhtDiscovery::hash_for_key("one"));

    ASSERT_TRUE(node.start());
    d->set_keys({"three", "two", "three"});
    EXPECT_EQ(d->discovery_hashes(),
              (std::vector<InfoHash>{DhtDiscovery::hash_for_key("three"), DhtDiscovery::hash_for_key("two")}));
    d->set_keys(std::vector<std::string>{});
    EXPECT_TRUE(d->discovery_hashes().empty());
    node.stop();
}

// A key set as the node runs is searched at once, not at the next round: two
// nodes that have no key alike meet as soon as one seeks the other's — one
// that only announces it, and seeks nobody — announced as its DHT came to
// know a node, not lost to the bootstrap and left for a minute. (A third node,
// the seed, keeps the announce: a node's own search never asks itself.)
TEST(DhtDiscoveryTest, AKeySetAsItRunsIsSearchedAtOnce) {
    Node seed(listening_config());
    auto disc_seed = std::make_unique<DhtDiscovery>(disc_config({}));
    DhtDiscovery* ds = disc_seed.get();
    ds->set_keys(std::vector<std::string>{});
    seed.add_subsystem(std::move(disc_seed));
    ASSERT_TRUE(seed.start());
    ASSERT_TRUE(wait_for([&] { return ds->dht_port() != 0; }, 5s));
    const std::vector<HostEndpoint> bootstrap{HostEndpoint("127.0.0.1", ds->dht_port())};

    Node a(listening_config());
    auto cfg_a = disc_config(bootstrap);
    cfg_a.search_interval = 60s;
    cfg_a.announce_interval = 60s;
    auto disc_a = std::make_unique<DhtDiscovery>(cfg_a);
    disc_a->set_keys(std::vector<DhtDiscovery::Key>{{"meet-here", DhtDiscovery::Use::Announce}});
    a.add_subsystem(std::move(disc_a));
    ASSERT_TRUE(a.start());

    // b searches and announces once a minute: only a key new goes at once.
    Node b(listening_config());
    auto cfg_b = disc_config(bootstrap);
    cfg_b.keys = {"elsewhere"};
    cfg_b.search_interval = 60s;
    cfg_b.announce_interval = 60s;
    auto disc_b = std::make_unique<DhtDiscovery>(cfg_b);
    DhtDiscovery* db = disc_b.get();
    b.add_subsystem(std::move(disc_b));
    ASSERT_TRUE(b.start());

    std::this_thread::sleep_for(2s);
    EXPECT_EQ(a.peer_count(), 0u);
    EXPECT_EQ(b.peer_count(), 0u);

    db->set_keys(std::vector<DhtDiscovery::Key>{{"elsewhere"}, {"meet-here", DhtDiscovery::Use::Search}});
    EXPECT_TRUE(wait_for([&] { return a.peer_count() >= 1 && b.peer_count() >= 1; }, 20s))
        << "a=" << a.peer_count() << " b=" << b.peer_count();

    b.stop();
    a.stop();
    seed.stop();
}

// A key announced alone seeks nobody: what its announces hand back (an announce
// is a search first) is not dialed. Put to search as well, the same key is.
TEST(DhtDiscoveryTest, AKeyAnnouncedAloneDialsNobody) {
    SilentPort mapped;
    // The seed keeps both announces: a node's own search never asks itself.
    Node seed(listening_config());
    auto disc_seed = std::make_unique<DhtDiscovery>(disc_config({}));
    DhtDiscovery* ds = disc_seed.get();
    ds->set_keys(std::vector<std::string>{});
    seed.add_subsystem(std::move(disc_seed));
    ASSERT_TRUE(seed.start());
    ASSERT_TRUE(wait_for([&] { return ds->dht_port() != 0; }, 5s));
    const std::vector<HostEndpoint> bootstrap{HostEndpoint("127.0.0.1", ds->dht_port())};

    // b announces the port the router forwards to it, where nothing answers.
    Node b(listening_config());
    b.add_subsystem(std::make_unique<FakePortMapping>(mapped.port()));
    auto disc_b = std::make_unique<DhtDiscovery>(disc_config(bootstrap));
    disc_b->set_keys(std::vector<DhtDiscovery::Key>{{"meet-here", DhtDiscovery::Use::Announce}});
    b.add_subsystem(std::move(disc_b));
    ASSERT_TRUE(b.start());
    std::this_thread::sleep_for(2s);

    // a announces the same key every second — each announce a lookup that
    // hands b's port back — and dials none of it.
    Node a(listening_config());
    auto disc_a = std::make_unique<DhtDiscovery>(disc_config(bootstrap));
    DhtDiscovery* da = disc_a.get();
    da->set_keys(std::vector<DhtDiscovery::Key>{{"meet-here", DhtDiscovery::Use::Announce}});
    a.add_subsystem(std::move(disc_a));
    ASSERT_TRUE(a.start());
    std::this_thread::sleep_for(5s);
    EXPECT_EQ(mapped.initials(), 0) << "a key announced alone dialed what it found";

    // The same key searched too: b's port is found, and dialed.
    da->set_keys(std::vector<DhtDiscovery::Key>{{"meet-here", DhtDiscovery::Use::Both}});
    EXPECT_TRUE(wait_for([&] { return mapped.initials() > 0; }, 15s));

    a.stop();
    b.stop();
    seed.stop();
}

// An announce made while the node's DHT knows no node goes nowhere: it waits
// until the DHT knows one, not until the next announce a minute on.
TEST(DhtDiscoveryTest, AnAnnounceWaitsForTheDhtToKnowANode) {
    // a knows no node (nothing answers where it bootstraps) until b asks it.
    Node a(listening_config());
    auto cfg_a = disc_config({HostEndpoint("127.0.0.1", 9)});
    cfg_a.search_interval = 60s;
    cfg_a.announce_interval = 60s;
    auto disc_a = std::make_unique<DhtDiscovery>(cfg_a);
    DhtDiscovery* da = disc_a.get();
    da->set_keys(std::vector<DhtDiscovery::Key>{{"meet-here", DhtDiscovery::Use::Announce}});
    a.add_subsystem(std::move(disc_a));
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(wait_for([&] { return da->dht_port() != 0; }, 5s));
    std::this_thread::sleep_for(1s);

    // b keeps what a announces once a knows it; c asks b.
    Node b(listening_config());
    auto disc_b = std::make_unique<DhtDiscovery>(disc_config({HostEndpoint("127.0.0.1", da->dht_port())}));
    DhtDiscovery* db = disc_b.get();
    db->set_keys(std::vector<std::string>{});
    b.add_subsystem(std::move(disc_b));
    ASSERT_TRUE(b.start());
    ASSERT_TRUE(wait_for([&] { return db->dht_port() != 0; }, 5s));
    std::this_thread::sleep_for(2s);

    Node c(listening_config());
    auto disc_c = std::make_unique<DhtDiscovery>(disc_config({HostEndpoint("127.0.0.1", db->dht_port())}));
    disc_c->set_keys(std::vector<DhtDiscovery::Key>{{"meet-here", DhtDiscovery::Use::Search}});
    c.add_subsystem(std::move(disc_c));
    ASSERT_TRUE(c.start());

    EXPECT_TRUE(wait_for([&] { return a.peer_count() >= 1 && c.peer_count() >= 1; }, 20s))
        << "a=" << a.peer_count() << " c=" << c.peer_count();

    c.stop();
    b.stop();
    a.stop();
}

// A port the router forwards to the node's is the one announced: whoever finds
// the node dials that.
TEST(DhtDiscoveryTest, AnnouncesThePortTheRouterForwards) {
    SilentPort mapped;
    Node a(listening_config());
    std::mutex failed_mutex;
    std::vector<Address> failed;
    a.on_dial_failed([&](const Address& address) {
        std::lock_guard<std::mutex> lock(failed_mutex);
        failed.push_back(address);
    });
    auto disc_a = std::make_unique<DhtDiscovery>(disc_config({}));
    DhtDiscovery* da = disc_a.get();
    a.add_subsystem(std::move(disc_a));
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(wait_for([&] { return da->dht_port() != 0; }, 5s));

    // b's announce is stored at a's DHT node, which a's searches ask.
    Node b(listening_config());
    // Told before discovery starts, so that the router's port is the only one
    // announced.
    b.add_subsystem(std::make_unique<FakePortMapping>(mapped.port()));
    b.add_subsystem(std::make_unique<DhtDiscovery>(
        disc_config({HostEndpoint("127.0.0.1", da->dht_port())})));
    ASSERT_TRUE(b.start());

    EXPECT_TRUE(wait_for([&] { return mapped.initials() > 0; }, 30s));
    EXPECT_TRUE(wait_for([&] {
        std::lock_guard<std::mutex> lock(failed_mutex);
        return std::any_of(failed.begin(), failed.end(),
                           [&](const Address& f) { return f.port == mapped.port(); });
    }, 10s));

    b.stop();
    a.stop();
}

// Where STUN sees the shared datagram socket is the port announced: a NAT that
// maps it to another one is dialed there.
TEST(DhtDiscoveryTest, AnnouncesThePortStunSeesTheSharedSocketAt) {
    SilentPort mapped;
    FixedStunServer stun("1.2.3.4", mapped.port());
    ASSERT_TRUE(stun.start());

    Node a(listening_config());
    auto disc_a = std::make_unique<DhtDiscovery>(disc_config({}));
    DhtDiscovery* da = disc_a.get();
    a.add_subsystem(std::move(disc_a));
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(wait_for([&] { return da->dht_port() != 0; }, 5s));

    Node b(listening_config());
    auto cfg = disc_config({HostEndpoint("127.0.0.1", da->dht_port())});
    cfg.discover_external_ip = true;
    cfg.stun_servers = {HostEndpoint("127.0.0.1", stun.port())};
    b.add_subsystem(std::make_unique<DhtDiscovery>(cfg));
    ASSERT_TRUE(b.start());

    EXPECT_TRUE(wait_for([&] { return mapped.initials() > 0; }, 30s));

    b.stop();
    a.stop();
    stun.stop();
}

// A node's own addresses — this host's, where STUN sees it, the router's — at
// a port of its own are told from others': a key it announces and searches
// hands them back, and they are not dialed. Another node on this host listens
// at another port, and another host at the same port is another's.
TEST(DhtDiscoveryTest, ItsOwnAddressesAreToldFromOthers) {
    FixedStunServer stun("9.9.9.9", 41234);
    ASSERT_TRUE(stun.start());

    Node a(listening_config());
    a.add_subsystem(std::make_unique<FakePortMapping>(40001));  // the router's 1.2.3.4:40001
    auto cfg = disc_config({});
    cfg.discover_external_ip = true;
    cfg.stun_servers = {HostEndpoint("127.0.0.1", stun.port())};
    auto disc = std::make_unique<DhtDiscovery>(cfg);
    DhtDiscovery* d = disc.get();
    a.add_subsystem(std::move(disc));
    ASSERT_TRUE(a.start());
    const uint16_t listen = a.listen_port();
    const IpAddress loopback = *IpAddress::parse("127.0.0.1");

    EXPECT_TRUE(d->is_own(Address{loopback, listen}));
    EXPECT_TRUE(d->is_own(Address{*IpAddress::parse("::1"), listen}));
    EXPECT_TRUE(d->is_own(Address{*IpAddress::parse("1.2.3.4"), 40001}));
    EXPECT_TRUE(wait_for([&] { return d->is_own(Address{*IpAddress::parse("9.9.9.9"), 41234}); }, 10s))
        << "where STUN sees the shared socket";

    EXPECT_FALSE(d->is_own(Address{loopback, static_cast<uint16_t>(listen + 1)})) << "another node here";
    if (listen != 41234 && listen != 40001)
        EXPECT_FALSE(d->is_own(Address{*IpAddress::parse("9.9.9.9"), listen}))
            << "another device behind the same NAT, at our listen port";
    EXPECT_FALSE(d->is_own(Address{*IpAddress::parse("5.6.7.8"), listen})) << "another host";
    EXPECT_FALSE(d->is_own(Address{*IpAddress::parse("1.2.3.4"), 40002}));

    a.stop();
    stun.stop();
}

// A peer found and not reached is dialed again as found again: a punch, dense
// probes, which two nodes behind NATs get through on once their dials cross.
TEST(DhtDiscoveryTest, PunchesAPeerFoundAndNotReached) {
    SilentPort mapped;
    Node a(listening_config());
    auto cfg = disc_config({});
    cfg.redial_every = 200ms;
    auto disc_a = std::make_unique<DhtDiscovery>(cfg);
    DhtDiscovery* da = disc_a.get();
    a.add_subsystem(std::move(disc_a));
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(wait_for([&] { return da->dht_port() != 0; }, 5s));

    Node b(listening_config());
    b.add_subsystem(std::make_unique<FakePortMapping>(mapped.port()));
    b.add_subsystem(std::make_unique<DhtDiscovery>(
        disc_config({HostEndpoint("127.0.0.1", da->dht_port())})));
    ASSERT_TRUE(b.start());

    // The first dial's three Initials, then a punch's eight.
    EXPECT_TRUE(wait_for([&] { return mapped.initials() >= 3 + 8; }, 30s))
        << mapped.initials() << " Initials";

    b.stop();
    a.stop();
}

// A peer found once — the next search a minute on — is punched all the same,
// every redial_every in its first stretch: two behind NATs that punched only
// as they found each other again (once a round) might never overlap.
TEST(DhtDiscoveryTest, PunchesAPeerFoundOnceOnItsOwnTime) {
    SilentPort mapped;
    // The seed keeps b's announce: a node's own search never asks itself.
    Node seed(listening_config());
    auto disc_seed = std::make_unique<DhtDiscovery>(disc_config({}));
    DhtDiscovery* ds = disc_seed.get();
    ds->set_keys(std::vector<std::string>{});
    seed.add_subsystem(std::move(disc_seed));
    ASSERT_TRUE(seed.start());
    ASSERT_TRUE(wait_for([&] { return ds->dht_port() != 0; }, 5s));
    const std::vector<HostEndpoint> bootstrap{HostEndpoint("127.0.0.1", ds->dht_port())};

    // b announces the port the router forwards to it, where nothing answers.
    Node b(listening_config());
    b.add_subsystem(std::make_unique<FakePortMapping>(mapped.port()));
    auto cfg_b = disc_config(bootstrap);
    cfg_b.search_interval = 60s;
    cfg_b.announce_interval = 60s;
    auto disc_b = std::make_unique<DhtDiscovery>(cfg_b);
    disc_b->set_keys(std::vector<DhtDiscovery::Key>{{"meet-here", DhtDiscovery::Use::Announce}});
    b.add_subsystem(std::move(disc_b));
    ASSERT_TRUE(b.start());
    std::this_thread::sleep_for(2s);

    // c searches once, finds b's port, and is not handed it again for a minute.
    Node c(listening_config());
    auto cfg_c = disc_config(bootstrap);
    cfg_c.search_interval = 60s;
    cfg_c.announce_interval = 60s;
    cfg_c.redial_every = 2s;
    cfg_c.redial_for = 20s;
    auto disc_c = std::make_unique<DhtDiscovery>(cfg_c);
    disc_c->set_keys(std::vector<DhtDiscovery::Key>{{"meet-here", DhtDiscovery::Use::Search}});
    c.add_subsystem(std::move(disc_c));
    ASSERT_TRUE(c.start());

    // The first dial's three Initials, then three punches of eight — where
    // finding it alone gave one punch at most.
    EXPECT_TRUE(wait_for([&] { return mapped.initials() >= 3 + 3 * 8; }, 15s))
        << mapped.initials() << " Initials";

    c.stop();
    b.stop();
    seed.stop();
}

// Dual-stack: the subsystem brings up BOTH a v4 and a v6 Kademlia network, each on
// its own UDP socket (BEP 32). Skipped only on hosts with no IPv6 loopback.
TEST(DhtDiscoveryTest, BringsUpBothAddressFamilies) {
    if (!ipv6_loopback_available()) GTEST_SKIP() << "host has no IPv6 loopback";

    Node node(listening_config());
    auto cfg = disc_config({});  // offline, no bootstrap
    cfg.bind_address = "";       // wildcard so both families bind freely
    auto disc = std::make_unique<DhtDiscovery>(cfg);
    DhtDiscovery* d = disc.get();
    node.add_subsystem(std::move(disc));

    ASSERT_TRUE(node.start());
    EXPECT_TRUE(wait_for([&] { return d->dht_port() != 0 && d->dht_port_v6() != 0; }, 5s))
        << "v4 port=" << d->dht_port() << " v6 port=" << d->dht_port_v6();
    node.stop();
    EXPECT_FALSE(d->is_running());
}

// The routing table is persisted under the configured data_dir, not the cwd.
TEST(DhtDiscoveryTest, PersistsRoutingTableUnderDataDir) {
    const std::string dir  = "rats_test_dht_data";
    const std::string path = dir + "/dht_routing.json";  // port-independent name
    delete_file(path.c_str());

    Node node(listening_config());
    auto cfg = disc_config({});  // offline, no bootstrap
    cfg.data_dir = dir;
    cfg.dht_port = 46991;        // fixed port (binds predictably; not part of the file name)
    cfg.enable_ipv6 = false;     // a single routing file (no _v6 variant)
    auto disc = std::make_unique<DhtDiscovery>(cfg);
    DhtDiscovery* d = disc.get();
    node.add_subsystem(std::move(disc));

    ASSERT_TRUE(node.start());
    ASSERT_TRUE(wait_for([&] { return d->is_running() && d->dht_port() != 0; }, 5s));
    node.stop();  // DhtDiscovery::stop() → DhtClient::stop() saves the routing table

    EXPECT_FALSE(read_file_text_cpp(path).empty())
        << "routing table was not written under data_dir: " << path;
    delete_file(path.c_str());
}

// A host with only IPv4 can disable the v6 family and still run the IPv4 DHT.
TEST(DhtDiscoveryTest, RunsIPv4OnlyWhenIPv6Disabled) {
    Node node(listening_config());
    auto cfg = disc_config({});
    cfg.enable_ipv6 = false;
    auto disc = std::make_unique<DhtDiscovery>(cfg);
    DhtDiscovery* d = disc.get();
    node.add_subsystem(std::move(disc));

    ASSERT_TRUE(node.start());
    EXPECT_TRUE(wait_for([&] { return d->is_running() && d->dht_port() != 0; }, 5s));
    EXPECT_EQ(d->dht_port_v6(), 0);  // v6 family was not started
    node.stop();
}

// Two nodes discover each other purely over the IPv6 DHT and form an encrypted
// link, their TCP listeners reachable over IPv6 (dual-stack "::"). Offline.
TEST(DhtDiscoveryTest, TwoNodesDiscoverViaIPv6Dht) {
    if (!ipv6_loopback_available()) GTEST_SKIP() << "host has no IPv6 loopback";

    auto v6_node_config = [] {
        NodeConfig c;
        c.bind_address = "::";  // dual-stack listener so IPv6 dials are accepted
        c.security = NodeConfig::Security::Noise;
        c.protocol = librats_test::test_protocol();
        return c;
    };
    auto v6_disc_config = [](const std::vector<HostEndpoint>& bootstrap) {
        auto c = disc_config(bootstrap);
        c.bind_address = "";    // wildcard
        c.enable_ipv4 = false;  // IPv6-only DHT
        return c;
    };

    Node a(v6_node_config());
    auto disc_a = std::make_unique<DhtDiscovery>(v6_disc_config({}));  // seed: no bootstrap
    DhtDiscovery* da = disc_a.get();
    a.add_subsystem(std::move(disc_a));
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(wait_for([&] { return da->dht_port_v6() != 0; }, 5s));

    Node b(v6_node_config());
    std::vector<HostEndpoint> bootstrap{ HostEndpoint("::1", da->dht_port_v6()) };
    b.add_subsystem(std::make_unique<DhtDiscovery>(v6_disc_config(bootstrap)));
    ASSERT_TRUE(b.start());

    EXPECT_TRUE(wait_for([&] { return a.peer_count() >= 1 && b.peer_count() >= 1; }, 30s))
        << "discovered: a=" << a.peer_count() << " b=" << b.peer_count();

    b.stop();
    a.stop();
}
