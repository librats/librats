#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/dht_discovery.h"
#include "nat/stun.h"
#include "core/socket.h"
#include "util/fs.h"

#include <atomic>
#include <chrono>
#include <memory>
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
        std::this_thread::sleep_for(5ms);
    }
    return pred();
}

// A loopback STUN server that always reports a fixed (public) reflexive address,
// so we can exercise the STUN → DHT node-id seeding path entirely offline.
class FixedStunServer {
public:
    explicit FixedStunServer(std::string public_ip) : public_ip_(std::move(public_ip)) {}
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
        if (is_valid_socket(socket_)) { close_socket(socket_); socket_ = INVALID_SOCKET_VALUE; }
        if (thread_.joinable()) thread_.join();
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
            resp.add_xor_mapped_address(StunMappedAddress(StunAddressFamily::IPv4, public_ip_, 41234));
            resp.add_software("FixedStunServer/1.0");
            auto out = resp.serialize();
            send_udp_data(socket_, out, sender.ip, sender.port);
        }
    }

    std::string       public_ip_;
    std::atomic<bool> running_{false};
    socket_t          socket_ = INVALID_SOCKET_VALUE;
    int               port_ = 0;
    std::thread       thread_;
};

NodeConfig listening_config() {
    NodeConfig c; c.bind_address = "127.0.0.1"; c.security = NodeConfig::Security::Noise; return c;
}

DhtDiscovery::Config disc_config(const std::vector<Address>& bootstrap) {
    DhtDiscovery::Config c;
    c.discovery_key = "librats-test-net";
    c.bind_address = "127.0.0.1";
    c.bootstrap_nodes = bootstrap;
    c.search_interval = 500ms;
    c.announce_interval = 1000ms;
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
    cfg.stun_servers = { Address("127.0.0.1", stun.port()) };
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
    cfg.stun_servers = { Address("127.0.0.1", 1) };  // nothing is listening there
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
    std::vector<Address> bootstrap{ Address("127.0.0.1", da->dht_port()) };
    b.add_subsystem(std::make_unique<DhtDiscovery>(disc_config(bootstrap)));
    ASSERT_TRUE(b.start());

    EXPECT_TRUE(wait_for([&] { return a.peer_count() >= 1 && b.peer_count() >= 1; }, 30s))
        << "discovered: a=" << a.peer_count() << " b=" << b.peer_count();

    b.stop();
    a.stop();
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
    const std::string path = dir + "/dht_routing_46991.json";
    delete_file(path.c_str());

    Node node(listening_config());
    auto cfg = disc_config({});  // offline, no bootstrap
    cfg.data_dir = dir;
    cfg.dht_port = 46991;        // fixed port → predictable file name
    cfg.enable_ipv6 = false;     // a single, predictably-named routing file
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
        return c;
    };
    auto v6_disc_config = [](const std::vector<Address>& bootstrap) {
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
    std::vector<Address> bootstrap{ Address("::1", da->dht_port_v6()) };
    b.add_subsystem(std::make_unique<DhtDiscovery>(v6_disc_config(bootstrap)));
    ASSERT_TRUE(b.start());

    EXPECT_TRUE(wait_for([&] { return a.peer_count() >= 1 && b.peer_count() >= 1; }, 30s))
        << "discovered: a=" << a.peer_count() << " b=" << b.peer_count();

    b.stop();
    a.stop();
}
