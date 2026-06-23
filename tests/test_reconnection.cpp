#include <gtest/gtest.h>

#include "node/node.h"
#include "subsystems/reconnection.h"
#include "peer/peer_book.h"
#include "util/fs.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <thread>

using namespace librats;
using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 15s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(2ms);
    }
    return pred();
}

NodeConfig listening_config() {
    NodeConfig c; c.bind_address = "127.0.0.1"; c.security = NodeConfig::Security::Noise; return c;
}
NodeConfig dialing_config() { NodeConfig c = listening_config(); c.enable_listen = false; return c; }

ReconnectionService::Config fast_reconnect() {
    ReconnectionService::Config c;
    c.tick = 100ms;
    c.base_backoff = 100ms;
    c.dial_timeout = 2s;  // backstop for an in-flight dial; keeps give-up bounded if a
                          // failed-dial event is slow, while still > any loopback handshake
    return c;
}

} // namespace

namespace {
const PeerRecord* find_record(const std::vector<PeerRecord>& recs, const std::string& addr) {
    for (const auto& r : recs) if (r.address.to_string() == addr) return &r;
    return nullptr;
}
} // namespace

// The book round-trips addresses AND their metadata (incl. IPv6) through a file.
TEST(PeerBookTest, RoundTripWithMetadata) {
    const std::string path = "rats_test_book.txt";
    delete_file(path.c_str());
    {
        PeerBook book(path);
        book.note_connected(*Address::parse("127.0.0.1:4001"), PeerId{}, /*now=*/1000);
        book.note_connected(*Address::parse("127.0.0.1:4001"), PeerId{}, /*now=*/2000);  // 2nd connect
        book.note_seen(*Address::parse("[::1]:5002"), /*now=*/1500);                      // IPv6, never connected
        book.save();
    }
    PeerBook book(path);
    book.load();
    EXPECT_EQ(book.size(), 2u);

    const auto recs = book.records();
    const PeerRecord* a = find_record(recs, "127.0.0.1:4001");
    ASSERT_NE(a, nullptr);
    EXPECT_EQ(a->connect_count, 2u);
    EXPECT_EQ(a->last_connected, 2000u);

    const PeerRecord* v6 = find_record(recs, "[::1]:5002");
    ASSERT_NE(v6, nullptr);              // IPv6 address survived the round-trip
    EXPECT_EQ(v6->last_connected, 0u);  // seen but never connected
    delete_file(path.c_str());
}

// remove() takes an address back out of the book.
TEST(PeerBookTest, Remove) {
    const std::string path = "rats_test_book_remove.txt";
    delete_file(path.c_str());
    PeerBook book(path);
    book.note_seen(*Address::parse("127.0.0.1:4001"), 1);
    book.note_seen(*Address::parse("10.0.0.5:5002"), 1);
    EXPECT_TRUE(book.remove(*Address::parse("127.0.0.1:4001")));
    EXPECT_FALSE(book.remove(*Address::parse("127.0.0.1:4001")));  // already gone
    EXPECT_EQ(book.size(), 1u);
    delete_file(path.c_str());
}

// best() ranks ever-connected peers first, most-recently-connected ahead of older.
TEST(PeerBookTest, BestRanking) {
    PeerBook book("");  // memory only (empty path → save/load no-op)
    book.note_seen(*Address::parse("10.0.0.1:1"), 100);                          // never connected
    book.note_connected(*Address::parse("10.0.0.2:2"), PeerId{}, 200);           // connected, older
    book.note_connected(*Address::parse("10.0.0.3:3"), PeerId{}, 300);           // connected, newest

    const auto top = book.best(/*n=*/3, /*now=*/300, /*max_age=*/0);
    ASSERT_EQ(top.size(), 3u);
    EXPECT_EQ(top[0].to_string(), "10.0.0.3:3");  // most recently connected
    EXPECT_EQ(top[1].to_string(), "10.0.0.2:2");  // connected, older
    EXPECT_EQ(top[2].to_string(), "10.0.0.1:1");  // never connected → last
}

// prune() drops stale records (by age) and caps the total size, keeping the best.
TEST(PeerBookTest, PruneByAgeAndSize) {
    PeerBook book("");
    book.note_connected(*Address::parse("10.0.0.1:1"), PeerId{}, /*now=*/1000);  // fresh
    book.note_connected(*Address::parse("10.0.0.2:2"), PeerId{}, /*now=*/10);    // ancient

    // now=1000, max_age=100 → the ancient one (last_seen=10) is stale.
    EXPECT_EQ(book.prune(/*now=*/1000, /*max_age=*/100, /*max_size=*/0), 1u);
    EXPECT_EQ(book.size(), 1u);

    // Add two more, then cap to 1: only the single best survives.
    book.note_connected(*Address::parse("10.0.0.3:3"), PeerId{}, 1000);
    book.note_seen(*Address::parse("10.0.0.4:4"), 1000);
    EXPECT_GE(book.prune(/*now=*/1000, /*max_age=*/0, /*max_size=*/1), 2u);
    EXPECT_EQ(book.size(), 1u);
}

// After a connection drops, the service re-dials the target and reconnects.
TEST(ReconnectionServiceTest, ReestablishesAfterDrop) {
    Node server(listening_config());
    Node client(dialing_config());

    auto reconnect = std::make_unique<ReconnectionService>(fast_reconnect());
    ReconnectionService* svc = reconnect.get();
    client.add_subsystem(std::move(reconnect));

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    svc->add(*Address::parse("127.0.0.1:" + std::to_string(server.listen_port())));
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; })) << "initial connect failed";

    // Force a drop from the client side.
    auto peer = client.peer(server.local_id());
    ASSERT_TRUE(peer.has_value());
    peer->disconnect();
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 0; })) << "did not drop";

    // The reconnection service should bring it back (server is still up).
    EXPECT_TRUE(wait_for([&] { return client.peer_count() == 1; })) << "did not reconnect";

    client.stop();
    server.stop();
}

// A peer can be connected over a link we did NOT initiate: here the other node
// dials us, so from our side it is an inbound link and the on_peer_connected event
// carries no dial address for it. The service must still recognise that peer as
// connected — via the live-peer snapshot — and must NOT keep re-dialing it. With
// the old flag-only logic this churned endless duplicate connections and, with
// max_attempts set, eventually reaped the target while the peer was still up.
TEST(ReconnectionServiceTest, DoesNotRedialPeerConnectedOverInboundLink) {
    Node us(listening_config());
    Node them(listening_config());

    auto cfg = fast_reconnect();
    cfg.max_attempts = 2;     // with the bug the churn would burn through these and
    cfg.dial_timeout = 1s;    // give up within ~max_attempts * dial_timeout
    auto reconnect = std::make_unique<ReconnectionService>(cfg);
    ReconnectionService* svc = reconnect.get();
    us.add_subsystem(std::move(reconnect));

    ASSERT_TRUE(us.start());
    ASSERT_TRUE(them.start());

    // They dial us → inbound from our point of view, a route we never initiated.
    const Address us_addr = *Address::parse("127.0.0.1:" + std::to_string(us.listen_port()));
    them.connect(us_addr);
    ASSERT_TRUE(wait_for([&] { return us.peer_count() == 1; })) << "inbound connect failed";

    // Ask the service to keep that same peer connected, by its dialable address.
    const Address them_addr = *Address::parse("127.0.0.1:" + std::to_string(them.listen_port()));
    svc->add(them_addr);
    ASSERT_EQ(svc->target_count(), 1u);

    // Long enough that the buggy churn would have given up and dropped the target.
    std::this_thread::sleep_for(3s);

    EXPECT_EQ(svc->target_count(), 1u) << "target reaped despite the peer being connected";
    EXPECT_EQ(us.peer_count(), 1u)     << "peer count disturbed by redundant dialing";

    us.stop();
    them.stop();
}

// A peer that connects and then drops again BEFORE the reconnection loop's periodic
// tick can ever sample it as live must still be re-dialed promptly. The dial's
// in-flight flag is cleared on the connect event (the success-side mirror of the
// failed-dial signal); without that it stays armed until dial_timeout, stalling the
// redial for seconds even though the address is plainly reachable.
TEST(ReconnectionServiceTest, RedialsPromptlyAfterDropBetweenTicks) {
    Node server(listening_config());
    Node client(dialing_config());

    ReconnectionService::Config cfg;
    cfg.base_backoff = 50ms;
    cfg.tick         = 2s;    // wide tick: the connect→drop never races a live-set sample,
    cfg.dial_timeout = 10s;   //   and the buggy in-flight stall would last this long.
    auto reconnect = std::make_unique<ReconnectionService>(cfg);
    ReconnectionService* svc = reconnect.get();
    client.add_subsystem(std::move(reconnect));

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    svc->add(*Address::parse("127.0.0.1:" + std::to_string(server.listen_port())));
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; })) << "initial connect failed";

    // Drop it at once — within the (wide) tick, so the loop never samples this peer
    // as live. Only the on_connected event could have cleared the dial's in-flight
    // flag; if it didn't, the redial is stuck until dial_timeout (10s) expires it.
    auto peer = client.peer(server.local_id());
    ASSERT_TRUE(peer.has_value());
    peer->disconnect();
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 0; })) << "did not drop";

    // Must come back well before dial_timeout would have expired the stale flag.
    EXPECT_TRUE(wait_for([&] { return client.peer_count() == 1; }, 3s))
        << "did not reconnect promptly after a drop between ticks";

    client.stop();
    server.stop();
}

// remove() stops the service re-dialing an address after a drop.
TEST(ReconnectionServiceTest, RemoveStopsReconnect) {
    Node server(listening_config());
    Node client(dialing_config());

    auto reconnect = std::make_unique<ReconnectionService>(fast_reconnect());
    ReconnectionService* svc = reconnect.get();
    client.add_subsystem(std::move(reconnect));

    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    const Address addr = *Address::parse("127.0.0.1:" + std::to_string(server.listen_port()));
    svc->add(addr);
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; })) << "initial connect failed";

    // Stop reconnecting, then drop the live connection.
    svc->remove(addr);
    EXPECT_EQ(svc->target_count(), 0u);
    auto peer = client.peer(server.local_id());
    ASSERT_TRUE(peer.has_value());
    peer->disconnect();
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 0; })) << "did not drop";

    // It must stay down: no target means no re-dial (give it several ticks).
    std::this_thread::sleep_for(800ms);
    EXPECT_EQ(client.peer_count(), 0u) << "reconnected despite remove()";

    client.stop();
    server.stop();
}

// With max_attempts set, a target that never connects is given up on and dropped.
TEST(ReconnectionServiceTest, GivesUpAfterMaxAttempts) {
    Node client(dialing_config());

    auto cfg = fast_reconnect();
    cfg.max_attempts = 3;
    auto reconnect = std::make_unique<ReconnectionService>(cfg);
    ReconnectionService* svc = reconnect.get();
    client.add_subsystem(std::move(reconnect));
    ASSERT_TRUE(client.start());

    // Nothing is listening here, so every dial fails and the target never connects.
    svc->add(*Address::parse("127.0.0.1:1"));
    EXPECT_EQ(svc->target_count(), 1u);

    EXPECT_TRUE(wait_for([&] { return svc->target_count() == 0; }, 10s))
        << "service did not give up after max_attempts";

    client.stop();
}

// Outbound peers are auto-remembered (persist_discovered) and survive a restart
// of the dialing node via the on-disk store.
TEST(ReconnectionServiceTest, PersistsDiscoveredAcrossRestart) {
    const std::string store_path = "rats_test_reconnect_store.txt";
    delete_file(store_path.c_str());

    Node server(listening_config());
    ASSERT_TRUE(server.start());
    const std::string server_addr = "127.0.0.1:" + std::to_string(server.listen_port());

    // First run: client dials the server; the service should remember it.
    {
        Node client(dialing_config());
        auto cfg = fast_reconnect();
        cfg.store_path = store_path;
        auto reconnect = std::make_unique<ReconnectionService>(cfg);
        ReconnectionService* svc = reconnect.get();
        client.add_subsystem(std::move(reconnect));
        ASSERT_TRUE(client.start());
        svc->add(*Address::parse(server_addr));
        ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; }));
        client.stop();
    }

    // The book now records the server address as a peer we connected to.
    PeerBook book(store_path);
    book.load();
    EXPECT_GE(book.size(), 1u);
    const auto all = book.all();
    EXPECT_NE(std::find(all.begin(), all.end(), *Address::parse(server_addr)), all.end());
    const auto recs = book.records();
    const PeerRecord* rec = find_record(recs, server_addr);
    ASSERT_NE(rec, nullptr);
    EXPECT_GT(rec->last_connected, 0u);   // recorded as actually connected
    EXPECT_GE(rec->connect_count, 1u);

    // Second run: a fresh client with the same store reconnects with no explicit add().
    {
        Node client(dialing_config());
        auto cfg = fast_reconnect();
        cfg.store_path = store_path;
        client.add_subsystem(std::make_unique<ReconnectionService>(cfg));
        ASSERT_TRUE(client.start());
        EXPECT_TRUE(wait_for([&] { return client.peer_count() == 1; })) << "did not reconnect from store";
        client.stop();
    }

    server.stop();
    delete_file(store_path.c_str());
}

// known_peers() exposes the book as a passive reserve pool, ranking a peer we
// actually connected to at the top.
TEST(ReconnectionServiceTest, KnownPeersExposesBookPool) {
    const std::string store_path = "rats_test_known_pool.txt";
    delete_file(store_path.c_str());

    Node server(listening_config());
    ASSERT_TRUE(server.start());
    const Address server_addr = *Address::parse("127.0.0.1:" + std::to_string(server.listen_port()));

    Node client(dialing_config());
    auto cfg = fast_reconnect();
    cfg.store_path = store_path;
    auto reconnect = std::make_unique<ReconnectionService>(cfg);
    ReconnectionService* svc = reconnect.get();
    client.add_subsystem(std::move(reconnect));
    ASSERT_TRUE(client.start());

    EXPECT_TRUE(svc->known_peers(10).empty());  // nothing known yet
    svc->add(server_addr);
    ASSERT_TRUE(wait_for([&] { return client.peer_count() == 1; }));

    const auto pool = svc->known_peers(10);
    ASSERT_FALSE(pool.empty());
    EXPECT_EQ(pool[0].to_string(), server_addr.to_string());  // the connected peer ranks top

    client.stop();
    server.stop();
    delete_file(store_path.c_str());
}
