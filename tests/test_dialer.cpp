#include <gtest/gtest.h>

#include "librats/core/socket.h"
#include "librats/node/dialer.h"
#include "librats/security/identity.h"
#include "librats/security/plaintext_security.h"
#include "librats/transport/connection.h"
#include "librats/transport/reactor_pool.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>

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

/// A port nothing is listening on: bind one, read it back, hand it over closed.
/// A TCP dial there is refused immediately; a UDP one is simply never answered,
/// which is exactly how a network that swallows datagrams looks from here.
uint16_t dead_port() {
    socket_t s = create_tcp_server(0, 1, "127.0.0.1", AddressFamily::IPv4);
    EXPECT_TRUE(is_valid_socket(s));
    const auto port = static_cast<uint16_t>(get_bound_port(s));
    close_socket(s);
    return port;
}

/// A reactor pool plus the wiring Node normally provides: every attempt outcome
/// is fed back to the Dialer, which is what lets it move to the next transport
/// and report a target as failed exactly once.
class DialerHarness : public ConnectionDelegate {
public:
    DialerHarness(DialPolicy policy, bool with_udp)
        : security_(Identity::generate(), "test/1.0"), pool_(1, *this, security_) {
        init_socket_library();
        if (with_udp) {
            udp_ = create_udp_socket(0, "127.0.0.1", AddressFamily::IPv4);
            EXPECT_TRUE(is_valid_socket(udp_));
            pool_.listen_udp(udp_, AddressFamily::IPv4);
        }
        dialer_ = std::make_unique<Dialer>(pool_, policy,
                                           [this](const std::string&, uint16_t) { ++failures_; });
        pool_.start();
        dialer_->start();
    }

    ~DialerHarness() override {
        dialer_->stop();
        pool_.stop();
        if (is_valid_socket(udp_)) close_socket(udp_);
    }

    void dial(const std::string& host, uint16_t port) { dialer_->dial(host, port); }

    // — ConnectionDelegate: the same forwarding Node::on_established/on_closed do —
    void on_established(Connection& conn) override {
        ++established_;
        if (conn.role() == ConnRole::Outbound)
            dialer_->on_established(PeerRoute{conn.reactor_index(), conn.id()});
    }
    void on_frame(Connection&, const Frame&) override {}
    void on_closed(Connection& conn, CloseReason) override {
        if (conn.role() != ConnRole::Outbound) return;
        ++attempts_ended_;
        dialer_->on_closed(PeerRoute{conn.reactor_index(), conn.id()});
    }
    void on_dial_aborted(uint8_t reactor, ConnId id, const std::string&, uint16_t) override {
        ++attempts_ended_;
        dialer_->on_closed(PeerRoute{reactor, id});
    }

    Dialer& dialer() { return *dialer_; }

    std::atomic<int> failures_{0};       ///< targets reported as failed
    std::atomic<int> established_{0};
    std::atomic<int> attempts_ended_{0}; ///< individual attempts that resolved

private:
    PlaintextSecurity       security_;
    ReactorPool             pool_;
    std::unique_ptr<Dialer> dialer_;
    socket_t                udp_ = RATS_INVALID_SOCKET;
};

DialPolicy policy_for(TransportKind preferred, std::chrono::milliseconds fallback) {
    DialPolicy p;
    p.preferred      = preferred;
    p.fallback_delay = fallback;
    return p;
}

} // namespace

// However many transports were raced, a target that nobody could reach is
// reported once — a redial policy counts these, so a duplicate is a real bug.
TEST(DialerTest, ReportsFailureExactlyOncePerTarget) {
    DialerHarness h(policy_for(TransportKind::Udp, 200ms), /*with_udp=*/true);
    const uint16_t port = dead_port();

    h.dial("127.0.0.1", port);

    ASSERT_TRUE(wait_for([&] { return h.failures_.load() == 1; }))
        << "the dial never resolved (failures=" << h.failures_.load() << ")";
    EXPECT_GE(h.attempts_ended_.load(), 2) << "the fallback transport was never raced";

    // Nothing may arrive late: the second attempt resolving must not report again.
    std::this_thread::sleep_for(1s);
    EXPECT_EQ(h.failures_.load(), 1);
    EXPECT_EQ(h.dialer().in_flight(), 0u) << "attempt bookkeeping leaked";
}

// A dial with nowhere to go must not vanish silently — the caller is waiting on
// exactly one answer, and no attempt is ever started.
TEST(DialerTest, FailsImmediatelyWhenNoTransportIsEnabled) {
    DialPolicy policy = policy_for(TransportKind::Udp, 200ms);
    policy.allow_tcp  = false;
    policy.allow_udp  = false;

    DialerHarness h(policy, /*with_udp=*/true);
    h.dial("127.0.0.1", dead_port());

    EXPECT_EQ(h.failures_.load(), 1) << "a dial with no transport must still resolve";
    EXPECT_EQ(h.dialer().in_flight(), 0u);
    std::this_thread::sleep_for(300ms);
    EXPECT_EQ(h.attempts_ended_.load(), 0) << "something was dialed anyway";
}

// A zero fallback delay means "the preferred transport or nothing": the other one
// must not be brought in, not even when the first fails fast.
TEST(DialerTest, ZeroFallbackDelayTriesOnlyThePreferredTransport) {
    DialerHarness h(policy_for(TransportKind::Tcp, 0ms), /*with_udp=*/true);

    h.dial("127.0.0.1", dead_port());

    ASSERT_TRUE(wait_for([&] { return h.failures_.load() == 1; }, 5s));
    std::this_thread::sleep_for(500ms);
    EXPECT_EQ(h.attempts_ended_.load(), 1) << "the fallback ran despite being disabled";
    EXPECT_EQ(h.failures_.load(), 1);
}

// A transport the pool cannot provide never becomes an attempt at all, so the
// next one takes its place at once — waiting out a fallback delay for a dial that
// was never started would be pure latency.
TEST(DialerTest, SkipsAnUnavailableTransportWithoutWaitingForTheFallback) {
    // Prefer UDP, but give the pool no datagram socket to dial from.
    DialerHarness h(policy_for(TransportKind::Udp, 30s), /*with_udp=*/false);

    const auto start = std::chrono::steady_clock::now();
    h.dial("127.0.0.1", dead_port());

    ASSERT_TRUE(wait_for([&] { return h.failures_.load() == 1; }, 10s))
        << "the dial stalled behind a fallback delay for a transport that was never tried";
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, 10s);
    EXPECT_EQ(h.attempts_ended_.load(), 1) << "only the reachable transport should be attempted";
}

// An unresolvable host dies before there is ever a Connection to report it on.
// The dialer still has to hear about it, or the target would wait out the
// establish deadline for an attempt that never began.
TEST(DialerTest, AnAbortedDialStillResolvesTheTarget) {
    DialPolicy policy = policy_for(TransportKind::Tcp, 0ms);
    DialerHarness h(policy, /*with_udp=*/false);

    h.dial("no-such-host.invalid", 1234);

    ASSERT_TRUE(wait_for([&] { return h.failures_.load() == 1; }, 20s))
        << "a dial that never started never resolved";
    EXPECT_EQ(h.dialer().in_flight(), 0u);
}

// stop() drops every attempt, and start() must leave the dialer usable again —
// a Node can be restarted, and stale bookkeeping would strand the first redial.
TEST(DialerTest, SurvivesAStopStartCycle) {
    DialerHarness h(policy_for(TransportKind::Tcp, 0ms), /*with_udp=*/false);

    h.dial("127.0.0.1", dead_port());
    ASSERT_TRUE(wait_for([&] { return h.failures_.load() == 1; }, 5s));

    h.dialer().stop();
    EXPECT_EQ(h.dialer().in_flight(), 0u);

    h.dialer().start();
    h.dial("127.0.0.1", dead_port());
    ASSERT_TRUE(wait_for([&] { return h.failures_.load() == 2; }, 5s))
        << "the dialer stopped working after a restart";
}
