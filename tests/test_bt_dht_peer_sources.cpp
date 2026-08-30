#include <gtest/gtest.h>

#include "librats/bittorrent/torrent.h"
#include "librats/bittorrent/torrent_info.h"
#include "librats/bittorrent/reactor.h"
#include "librats/bittorrent/types.h"

#include <chrono>
#include <functional>
#include <string>
#include <utility>
#include <vector>

using namespace librats;
using namespace librats::bittorrent;

// A DHT announce is a get_peers traversal with a write at the end, so it discovers
// exactly the peers the torrent is looking for. Client used to call announce_peer()
// without a callback and drop every one of them, leaving a magnet to wait for the
// next find_peers round (~30 s) to be handed addresses the node already had. These
// tests pin the wiring at the TorrentHost seam: both DHT paths must hand the torrent
// a working sink, and peers arriving through either must be dialed.

namespace {

using PeerSink = std::function<void(const std::string& ip, std::uint16_t port)>;

class FakeHost final : public TorrentHost {
public:
    void connect_peer(Torrent&, const std::string& ip, std::uint16_t port) override {
        dialed.emplace_back(ip, port);
    }
    const PeerId& peer_id() const override { return id_; }
    std::uint16_t listen_port() const override { return 6881; }

    void find_peers_via_dht(const InfoHash&, PeerSink on_peer) override {
        ++find_calls;
        find_sink = std::move(on_peer);
    }
    void announce_to_dht(const InfoHash&, std::uint16_t port, PeerSink on_peer) override {
        ++announce_calls;
        announced_port = port;
        announce_sink  = std::move(on_peer);
    }

    bool dialed_contains(const std::string& ip, std::uint16_t port) const {
        for (const auto& d : dialed) if (d.first == ip && d.second == port) return true;
        return false;
    }

    std::vector<std::pair<std::string, std::uint16_t>> dialed;
    int           find_calls     = 0;
    int           announce_calls = 0;
    std::uint16_t announced_port = 0;
    PeerSink      find_sink;
    PeerSink      announce_sink;

private:
    PeerId id_{};
};

// Drive the torrent's own 1 s tick until `done` or `ms` elapse.
bool pump_until(Reactor& r, const std::function<bool()>& done, int ms) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < deadline) {
        r.run_one(5);
        if (done()) return true;
    }
    return done();
}

TorrentInfo magnet_info() {
    auto info = TorrentInfo::from_magnet(
        "magnet:?xt=urn:btih:911921a5d414bdff77246a6d42e1c359a8abd9f9");
    EXPECT_TRUE(info.has_value());
    return *info;
}

} // namespace

TEST(BtDhtPeerSources, AnnounceDeliversItsDiscoveredPeers) {
    Reactor  reactor;
    FakeHost host;
    Torrent  t(reactor, host, magnet_info(), "");
    t.start();

    // The announce goes out on tick 5 (Torrent::tick), so this waits ~5 s of real
    // ticks. There is no faster seam: the cadence is the thing under test's schedule.
    ASSERT_TRUE(pump_until(reactor, [&] { return host.announce_calls > 0; }, 15000))
        << "the torrent never announced itself to the DHT";
    EXPECT_EQ(host.announced_port, 6881);

    // The regression: before the fix announce_to_dht took no callback at all, so
    // there was nothing here to hand peers to.
    ASSERT_TRUE(host.announce_sink) << "announce was made without a peer sink — its "
                                       "get_peers results would be discarded";

    host.announce_sink("203.0.113.7", 51413);
    EXPECT_TRUE(host.dialed_contains("203.0.113.7", 51413))
        << "a peer discovered by the announce traversal was not dialed";

    t.stop();
}

TEST(BtDhtPeerSources, FindPeersDeliversItsPeers) {
    Reactor  reactor;
    FakeHost host;
    Torrent  t(reactor, host, magnet_info(), "");
    t.start();

    // get_peers goes out on tick 1.
    ASSERT_TRUE(pump_until(reactor, [&] { return host.find_calls > 0; }, 10000));
    ASSERT_TRUE(host.find_sink);

    host.find_sink("203.0.113.8", 6881);
    EXPECT_TRUE(host.dialed_contains("203.0.113.8", 6881));

    // Both sinks feed one list, so the same address arriving twice is dialed once.
    const std::size_t after_first = host.dialed.size();
    host.find_sink("203.0.113.8", 6881);
    EXPECT_EQ(host.dialed.size(), after_first) << "a duplicate address was re-dialed";

    t.stop();
}
