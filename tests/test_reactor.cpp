#include <gtest/gtest.h>

#include "librats/transport/reactor.h"
#include "librats/transport/connection.h"
#include "librats/wire/frame.h"
#include "librats/security/identity.h"
#include "librats/security/noise_security.h"
#include "librats/security/plaintext_security.h"
#include "librats/core/socket.h"
#include "librats/core/timer_queue.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/resource.h>
#endif

using namespace librats;
using namespace std::chrono_literals;

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout = 15s) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(1ms);
    }
    return pred();
}

/// Server-side delegate: bounce every frame straight back to the sender.
class EchoDelegate : public ConnectionDelegate {
public:
    void on_established(Connection&) override { established_++; }
    void on_frame(Connection& conn, const Frame& frame) override {
        conn.send(frame.header, frame.payload);
    }
    void on_closed(Connection&, CloseReason) override { closed_++; }
    std::atomic<int> established_{0};
    std::atomic<int> closed_{0};
};

/// Client-side delegate: record establishment, the remote id, and echoed payloads.
class CollectDelegate : public ConnectionDelegate {
public:
    void on_established(Connection& conn) override {
        last_conn_id_.store(conn.id());
        secure_.store(conn.is_secure());
        { std::lock_guard<std::mutex> lock(mutex_); remote_id_ = conn.remote_id(); }
        established_++;
    }
    void on_frame(Connection&, const Frame& frame) override {
        { std::lock_guard<std::mutex> lock(mutex_);
          received_.emplace_back(reinterpret_cast<const char*>(frame.payload.data()),
                                 frame.payload.size()); }
        frames_++;
    }
    void on_closed(Connection&, CloseReason) override { closed_++; }

    std::atomic<int>    established_{0};
    std::atomic<int>    frames_{0};
    std::atomic<int>    closed_{0};
    std::atomic<bool>   secure_{false};
    std::atomic<ConnId> last_conn_id_{kInvalidConnId};
    std::mutex               mutex_;
    PeerId                   remote_id_;
    std::vector<std::string> received_;
};

/// Raise the soft descriptor limit towards `wanted` and report what is available.
///
/// A single-process client+server test burns TWO descriptors per connection (the
/// dialled socket and the accepted one), so a 1000-connection run needs ~2000 —
/// well past the 1024 soft limit a login session commonly carries. Past the limit
/// socket()/accept() simply fail with EMFILE, which surfaces only as connections
/// that never establish, i.e. as a wait timeout with no visible error. Ask for
/// exactly what the test needs (not the hard limit: macOS caps the real ceiling at
/// kern.maxfilesperproc regardless of what RLIMIT_NOFILE claims).
size_t raise_fd_limit(size_t wanted) {
#ifdef _WIN32
    return wanted;  // Windows sockets are not charged against a per-process fd limit
#else
    rlimit rl{};
    if (::getrlimit(RLIMIT_NOFILE, &rl) != 0) return wanted;  // unknown: let the test run
    if (rl.rlim_cur < static_cast<rlim_t>(wanted)) {
        rlimit want = rl;
        want.rlim_cur = (rl.rlim_max == RLIM_INFINITY)
                            ? static_cast<rlim_t>(wanted)
                            : (std::min)(rl.rlim_max, static_cast<rlim_t>(wanted));
        if (::setrlimit(RLIMIT_NOFILE, &want) == 0) rl = want;
    }
    return rl.rlim_cur == RLIM_INFINITY ? wanted : static_cast<size_t>(rl.rlim_cur);
#endif
}

std::pair<socket_t, int> make_server() {
    socket_t s = create_tcp_server(0, 1024, "127.0.0.1", AddressFamily::IPv4);
    EXPECT_TRUE(is_valid_socket(s));
    return {s, get_bound_port(s)};
}

class ReactorTest : public ::testing::Test {
protected:
    void SetUp() override { init_socket_library(); }
};

} // namespace

// A single round trip over a plaintext handshake.
TEST_F(ReactorTest, EchoesSingleFrame) {
    auto [server_sock, port] = make_server();

    Identity sid = Identity::generate(), cid = Identity::generate();
    PlaintextSecurity ssec(sid), csec(cid);

    EchoDelegate echo;
    Reactor server(0, echo, ssec);
    server.listen(server_sock);
    server.start();

    CollectDelegate collect;
    Reactor client(1, collect, csec);
    client.start();

    client.connect("127.0.0.1", port);
    ASSERT_TRUE(wait_for([&] { return collect.established_.load() == 1; }))
        << "client never established";

    const ConnId conn = collect.last_conn_id_.load();
    const std::string msg = "hello reactor";
    client.execute([&, conn] { if (auto* c = client.find(conn)) c->send(0, ByteView(msg)); });

    ASSERT_TRUE(wait_for([&] { return collect.frames_.load() >= 1; })) << "no echo";
    {
        std::lock_guard<std::mutex> lock(collect.mutex_);
        ASSERT_EQ(collect.received_.size(), 1u);
        EXPECT_EQ(collect.received_[0], msg);
    }

    client.stop();
    server.stop();
}

// An encrypted round trip: each side learns the other's self-certifying PeerId,
// and the bytes on the wire are ciphertext.
TEST_F(ReactorTest, EncryptedEchoWithNoise) {
    auto [server_sock, port] = make_server();

    Identity sid = Identity::generate(), cid = Identity::generate();
    NoiseSecurity ssec(sid), csec(cid);

    EchoDelegate echo;
    Reactor server(0, echo, ssec);
    server.listen(server_sock);
    server.start();

    CollectDelegate collect;
    Reactor client(1, collect, csec);
    client.start();

    client.connect("127.0.0.1", port);
    ASSERT_TRUE(wait_for([&] { return collect.established_.load() == 1; }))
        << "encrypted handshake never completed";

    EXPECT_TRUE(collect.secure_.load());
    {
        std::lock_guard<std::mutex> lock(collect.mutex_);
        EXPECT_EQ(collect.remote_id_, sid.id);  // client proved the server's identity
    }

    const ConnId conn = collect.last_conn_id_.load();
    const std::string msg = "secret payload";
    client.execute([&, conn] { if (auto* c = client.find(conn)) c->send(0, ByteView(msg)); });

    ASSERT_TRUE(wait_for([&] { return collect.frames_.load() >= 1; })) << "no echo";
    std::lock_guard<std::mutex> lock(collect.mutex_);
    ASSERT_EQ(collect.received_.size(), 1u);
    EXPECT_EQ(collect.received_[0], msg);

    client.stop();
    server.stop();
}

// Many frames on one connection arrive in order and intact.
TEST_F(ReactorTest, EchoesManyFramesInOrder) {
    auto [server_sock, port] = make_server();

    Identity sid = Identity::generate(), cid = Identity::generate();
    PlaintextSecurity ssec(sid), csec(cid);

    EchoDelegate echo;
    Reactor server(0, echo, ssec);
    server.listen(server_sock);
    server.start();

    CollectDelegate collect;
    Reactor client(1, collect, csec);
    client.start();

    client.connect("127.0.0.1", port);
    ASSERT_TRUE(wait_for([&] { return collect.established_.load() == 1; }));

    const ConnId conn = collect.last_conn_id_.load();
    constexpr int kCount = 500;
    client.execute([&, conn] {
        auto* c = client.find(conn);
        if (!c) return;
        for (int i = 0; i < kCount; ++i) c->send(0, ByteView(std::to_string(i)));
    });

    ASSERT_TRUE(wait_for([&] { return collect.frames_.load() >= kCount; }))
        << "got " << collect.frames_.load() << "/" << kCount;

    std::lock_guard<std::mutex> lock(collect.mutex_);
    ASSERT_EQ(collect.received_.size(), static_cast<size_t>(kCount));
    for (int i = 0; i < kCount; ++i) EXPECT_EQ(collect.received_[i], std::to_string(i));

    client.stop();
    server.stop();
}

// Scale check: 1000 concurrent connections, each gets one echoed frame.
TEST_F(ReactorTest, Sustains1000Connections) {
    constexpr int kConns = 1000;

    // 2 fds per connection, plus slack for the listener, two epolls and two Notifiers.
    constexpr size_t kNeededFds = 2 * kConns + 64;
    const size_t fd_limit = raise_fd_limit(kNeededFds);
    if (fd_limit < kNeededFds)
        GTEST_SKIP() << kConns << " connections need " << kNeededFds
                     << " descriptors; the hard limit allows only " << fd_limit
                     << " (raise `ulimit -n`)";

    auto [server_sock, port] = make_server();

    Identity sid = Identity::generate(), cid = Identity::generate();
    PlaintextSecurity ssec(sid), csec(cid);

    EchoDelegate echo;
    Reactor server(0, echo, ssec);
    server.listen(server_sock);
    server.start();

    CollectDelegate collect;
    Reactor client(1, collect, csec);
    client.start();

    // Dial in waves so in-flight (not-yet-accepted) connects stay bounded —
    // isolates steady-state capacity from a transient connect storm.
    constexpr int kWave = 100;
    const auto t0 = std::chrono::steady_clock::now();
    for (int sent = 0; sent < kConns; sent += kWave) {
        const int n = (std::min)(kWave, kConns - sent);
        for (int i = 0; i < n; ++i) client.connect("127.0.0.1", port);
        ASSERT_TRUE(wait_for([&] { return collect.established_.load() >= sent + n; }, 20s))
            << "established " << collect.established_.load() << " after dialing " << (sent + n);
    }
    const auto t_conn = std::chrono::steady_clock::now();

    client.execute([&] {
        for (ConnId id = 1; id <= static_cast<ConnId>(kConns); ++id)
            if (auto* c = client.find(id)) c->send(0, ByteView(std::string("ping")));
    });
    ASSERT_TRUE(wait_for([&] { return collect.frames_.load() == kConns; }, 20s))
        << "echoed " << collect.frames_.load() << "/" << kConns;
    const auto t_echo = std::chrono::steady_clock::now();

    const auto connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t_conn - t0).count();
    const auto echo_ms    = std::chrono::duration_cast<std::chrono::milliseconds>(t_echo - t_conn).count();
    std::cout << "[ reactor ] " << kConns << " connections established in " << connect_ms
              << " ms; " << kConns << " round-trips in " << echo_ms << " ms\n";

    EXPECT_EQ(server.connection_count(), static_cast<size_t>(kConns));
    EXPECT_EQ(client.connection_count(), static_cast<size_t>(kConns));

    client.stop();
    server.stop();
    EXPECT_TRUE(wait_for([&] { return collect.closed_.load() == kConns; }));
}

// ── cancel_dial: where a dial stops being this node's alone to end ───────────
//
// A racing dial has to be cancellable, but only for as long as it is still a dial.
// The line is Established, and it is not an arbitrary one: we dial, so we are the
// Noise XX initiator, and an initiator reaches Established while still composing
// the third message. An attempt still handshaking here has therefore not sent it
// and cannot exist at the far end — dropping it is invisible over there. One that
// has established is a link both ends can see, and killing it unilaterally is how
// two nodes end up each tearing down the other's choice (see node/dialer.h).

// A server that accepts and then says nothing at all: the TCP connection comes up,
// the Noise handshake cannot. That is what pins the attempt in Handshaking for as
// long as the test needs, with no timing assumption at all.
TEST_F(ReactorTest, CancelDialDropsAnAttemptThatIsStillOnlyAnAttempt) {
    auto [silent_server, port] = make_server();

    Identity cid = Identity::generate();
    NoiseSecurity csec(cid);
    CollectDelegate collect;
    Reactor client(0, collect, csec);
    client.start();

    const ConnId id = client.connect("127.0.0.1", port);
    ASSERT_NE(id, kInvalidConnId);
    ASSERT_TRUE(wait_for([&] { return client.connection_count() == 1; }))
        << "the attempt never started";

    client.cancel_dial(id, CloseReason::DialSuperseded);

    ASSERT_TRUE(wait_for([&] { return collect.closed_.load() == 1; }, 5s))
        << "a cancelled attempt outlived its race";
    EXPECT_EQ(collect.established_.load(), 0);
    EXPECT_EQ(client.connection_count(), 0u);

    client.stop();
    close_socket(silent_server);
}

// The other half of the same rule, and the one this exists for: an attempt that
// won its own handshake before the cancellation reached it is no longer a dial,
// and cancel_dial() must leave it completely alone — still established, still
// carrying traffic. Deciding its fate is PeerTable::add's job, from a rule the far
// end applies to the same pair and reaches the same answer on.
TEST_F(ReactorTest, CancelDialSparesAnAttemptThatAlreadyEstablished) {
    auto [server_sock, port] = make_server();

    Identity sid = Identity::generate(), cid = Identity::generate();
    NoiseSecurity ssec(sid), csec(cid);

    EchoDelegate echo;
    Reactor server(0, echo, ssec);
    server.listen(server_sock);
    server.start();

    CollectDelegate collect;
    Reactor client(1, collect, csec);
    client.start();

    const ConnId id = client.connect("127.0.0.1", port);
    ASSERT_NE(id, kInvalidConnId);
    ASSERT_TRUE(wait_for([&] { return collect.established_.load() == 1; }))
        << "client never established";

    client.cancel_dial(id, CloseReason::DialSuperseded);

    // Not merely "still in the map": the link has to still work, because the peer
    // table may well decide this is the one to keep.
    const std::string msg = "spared";
    client.execute([&, id] { if (auto* c = client.find(id)) c->send(0, ByteView(msg)); });
    ASSERT_TRUE(wait_for([&] { return collect.frames_.load() >= 1; }, 5s))
        << "the spared connection stopped carrying traffic";
    EXPECT_EQ(collect.closed_.load(), 0) << "an established link was torn down by the dial race";
    EXPECT_EQ(client.connection_count(), 1u);

    // close() is unconditional, and stays that way — sparing is cancel_dial's rule,
    // not a property of the connection.
    client.close(id, CloseReason::LocalClose);
    EXPECT_TRUE(wait_for([&] { return collect.closed_.load() == 1; }, 5s))
        << "close() no longer closes an established connection";

    client.stop();
    server.stop();
}

// A stopped reactor can be started again, and what it gives up on the way out is
// what makes that safe. The listen sockets are the node's to close and it closes
// them after joining this thread, so every descriptor the loop registered is dead
// by the next start — and the kernel is free to hand that same number to something
// else. The TCP listener is handed over afresh by listen() before every start; the
// datagram socket is not, since only listen_udp() ever replaces the mux and the
// node skips that call whenever the UDP rebind failed ("this node runs TCP-only").
// A mux held across the gap would leave the reactor polling, recvfrom()-ing and
// sending on a socket it does not own, and still offering UDP dials it can no
// longer carry.
TEST_F(ReactorTest, StopForgetsTheDatagramSocket) {
    socket_t udp = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
    ASSERT_TRUE(is_valid_socket(udp));

    Identity id = Identity::generate();
    PlaintextSecurity sec(id);
    CollectDelegate collect;
    Reactor reactor(0, collect, sec);
    reactor.listen_udp(udp, AddressFamily::IPv4);
    ASSERT_TRUE(reactor.has_udp());

    reactor.start();
    reactor.stop();
    close_socket(udp);   // as the node does, after the join

    EXPECT_FALSE(reactor.has_udp())
        << "the reactor kept a mux wrapped around a closed descriptor";
    EXPECT_EQ(reactor.connect("127.0.0.1", 9, TransportKind::Udp), kInvalidConnId)
        << "a UDP dial was accepted with no datagram socket left to carry it";

    // The restart is what the forgetting is for: this loop must come up without
    // that socket rather than re-registering the one it handed back.
    reactor.start();
    EXPECT_FALSE(reactor.has_udp());
    reactor.stop();
}

// The same rule one level down. A timer outlives the loop that scheduled it unless
// the queue goes with it, and the reactor's maintenance sweep re-arms itself from
// its own callback: an entry surviving a stop would start a second, endless chain
// on the next start — N restarts, N+1 sweeps and N+1 timed wake-ups per interval,
// for as long as the node lives.
TEST(TimerQueueTest, ClearDropsEverythingPending) {
    TimerQueue timers;
    int fired = 0;

    timers.schedule(0ms, [&] { fired++; });
    const TimerId cancelled = timers.schedule(0ms, [&] { fired++; });
    timers.cancel(cancelled);
    ASSERT_FALSE(timers.empty());

    timers.clear();

    EXPECT_TRUE(timers.empty());
    EXPECT_EQ(timers.next_timeout_ms(50), 50);  // nothing due, so nothing to wake for
    timers.run_due();
    EXPECT_EQ(fired, 0) << "a timer survived the queue it was scheduled on";

    // Ids keep counting up across a clear, so no handle from before it can come to
    // name a timer scheduled after — including the tombstone left by that cancel().
    const TimerId fresh = timers.schedule(0ms, [&] { fired++; });
    EXPECT_NE(fresh, cancelled);
    timers.run_due();
    EXPECT_EQ(fired, 1) << "a stale tombstone swallowed a newly scheduled timer";
}
