/**
 * @file test_network_monitor.cpp
 * @brief Unit tests for NetworkMonitor and RatsClient network-change detection.
 *
 * Like the port-mapping tests, these do not depend on the test host actually
 * changing its network configuration. A real IP/interface change cannot be
 * forced in CI, so the focus is the lifecycle contract: the monitor starts,
 * tears down promptly without hanging or crashing, never fires the callback
 * when the address set is unchanged, and the RatsClient integration can be
 * toggled before and during a run.
 */

#include <gtest/gtest.h>
#include "network_monitor.h"
#include "network_utils.h"
#include "librats.h"
#include "socket.h"

#include <atomic>
#include <chrono>
#include <thread>

using namespace librats;

// ============================================================================
// NetworkMonitor (standalone)
// ============================================================================

class NetworkMonitorTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_TRUE(init_socket_library()); }
    void TearDown() override { cleanup_socket_library(); }
};

TEST_F(NetworkMonitorTest, StartStopIsClean) {
    NetworkMonitor monitor;
    std::atomic<int> changes{0};

    EXPECT_FALSE(monitor.is_running());
    monitor.start([&](const std::vector<std::string>&) { changes.fetch_add(1); });
    EXPECT_TRUE(monitor.is_running());

    // Teardown must be responsive even with the worker (and any reader) running.
    auto t0 = std::chrono::steady_clock::now();
    monitor.stop();
    auto elapsed = std::chrono::steady_clock::now() - t0;

    EXPECT_FALSE(monitor.is_running());
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 5);
}

TEST_F(NetworkMonitorTest, DoubleStartAndDoubleStopAreSafe) {
    NetworkMonitor monitor;
    monitor.start([](const std::vector<std::string>&) {});
    // A second start while already running must not spawn a second worker or throw.
    monitor.start([](const std::vector<std::string>&) {});
    EXPECT_TRUE(monitor.is_running());

    monitor.stop();
    monitor.stop(); // idempotent
    EXPECT_FALSE(monitor.is_running());
}

TEST_F(NetworkMonitorTest, DestructorStopsRunningMonitor) {
    // Leaving scope with a running monitor must not leak or hang.
    {
        NetworkMonitor monitor;
        monitor.start([](const std::vector<std::string>&) {});
        EXPECT_TRUE(monitor.is_running());
    }
    SUCCEED();
}

TEST_F(NetworkMonitorTest, NoSpuriousCallbackWithoutChange) {
    // The monitor snapshots the address set at start and must only invoke the
    // callback when that set actually changes. With a stable test host, even an
    // explicit check_now() (which coalesces/debounces exactly like a real OS
    // event) must not produce a callback.
    NetworkMonitor monitor;
    std::atomic<int> changes{0};
    monitor.set_debounce(std::chrono::milliseconds(50));
    monitor.start([&](const std::vector<std::string>&) { changes.fetch_add(1); });

    for (int i = 0; i < 3; ++i) {
        monitor.check_now();
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
    }
    // Allow the debounce + diff to settle.
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    monitor.stop();

    EXPECT_EQ(0, changes.load());
}

TEST_F(NetworkMonitorTest, CheckNowBeforeStartIsNoOp) {
    NetworkMonitor monitor;
    // Not running yet: must be a safe no-op, not a crash.
    monitor.check_now();
    EXPECT_FALSE(monitor.is_running());
}

TEST_F(NetworkMonitorTest, BackendModeQueryIsConsistent) {
    NetworkMonitor monitor;
    monitor.start([](const std::vector<std::string>&) {});
    // Whether event-driven or polling, the query must simply not crash and the
    // monitor must be running.
    bool event_driven = monitor.is_event_driven();
    (void)event_driven;
    EXPECT_TRUE(monitor.is_running());
    monitor.stop();
}

// ============================================================================
// RatsClient integration
// ============================================================================

class NetworkChangeDetectionTest : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_TRUE(init_socket_library()); }
    void TearDown() override { cleanup_socket_library(); }
};

TEST_F(NetworkChangeDetectionTest, EnabledByDefault) {
    RatsClient client(0);
    EXPECT_TRUE(client.is_network_change_detection_enabled());
}

TEST_F(NetworkChangeDetectionTest, DisableBeforeStart) {
    RatsClient client(0);
    client.set_network_change_detection_enabled(false);
    EXPECT_FALSE(client.is_network_change_detection_enabled());

    ASSERT_TRUE(client.start());
    // No monitor should have been started; stop must still be clean.
    client.stop();

    client.set_network_change_detection_enabled(true);
    EXPECT_TRUE(client.is_network_change_detection_enabled());
}

TEST_F(NetworkChangeDetectionTest, ToggleWhileRunningIsClean) {
    RatsClient client(0);
    ASSERT_TRUE(client.start());

    // Toggling at runtime tears down / brings up the monitor and must not hang.
    auto t0 = std::chrono::steady_clock::now();
    client.set_network_change_detection_enabled(false);
    EXPECT_FALSE(client.is_network_change_detection_enabled());
    client.set_network_change_detection_enabled(true);
    EXPECT_TRUE(client.is_network_change_detection_enabled());
    auto elapsed = std::chrono::steady_clock::now() - t0;
    EXPECT_LT(std::chrono::duration_cast<std::chrono::seconds>(elapsed).count(), 5);

    client.stop();
}

TEST_F(NetworkChangeDetectionTest, RegisterCallbackDoesNotCrash) {
    RatsClient client(0);
    std::atomic<int> changes{0};
    client.on_network_changed([&](const std::vector<std::string>&) {
        changes.fetch_add(1);
    });
    ASSERT_TRUE(client.start());
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    client.stop();
    // Callback may or may not fire depending on the host; the contract under test
    // is only that registration + lifecycle are safe.
    SUCCEED();
}

TEST_F(NetworkChangeDetectionTest, StartStopCyclesWithDetectionEnabled) {
    RatsClient client(0);
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(client.start());
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        client.stop();
    }
    SUCCEED();
}
