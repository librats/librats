#include <gtest/gtest.h>

#include "core/event_bus.h"
#include "core/service_registry.h"
#include "node/node.h"
#include "node/host_events.h"

#include <atomic>
#include <string>
#include <vector>

using namespace librats;

namespace {
struct Tick   { int n = 0; };
struct Reload { std::string name; };
}  // namespace

// All handlers for an event type fire, in registration order; other types don't.
TEST(EventBusTest, FanOutInOrderAndTypeIsolation) {
    EventBus bus;
    std::vector<int> order;
    bus.on<Tick>([&](const Tick& t) { order.push_back(t.n); });
    bus.on<Tick>([&](const Tick& t) { order.push_back(t.n * 10); });

    bool reload_seen = false;
    bus.on<Reload>([&](const Reload&) { reload_seen = true; });

    bus.emit(Tick{3});
    EXPECT_EQ(order, (std::vector<int>{3, 30}));  // both, in order
    EXPECT_FALSE(reload_seen);                    // Reload handler untouched

    bus.emit(Reload{"cfg"});
    EXPECT_TRUE(reload_seen);
}

// Emitting an event with no subscribers is a harmless no-op.
TEST(EventBusTest, EmitWithoutHandlers) {
    EventBus bus;
    EXPECT_NO_THROW(bus.emit(Tick{1}));
}

// A handler may subscribe (or emit) during dispatch without deadlocking — emit
// snapshots the handler list under the lock and invokes it unlocked.
TEST(EventBusTest, ReentrantSubscribeIsSafe) {
    EventBus bus;
    std::atomic<int> calls{0};
    bus.on<Tick>([&](const Tick&) {
        if (calls++ == 0) bus.on<Tick>([&](const Tick&) { calls++; });  // add during dispatch
    });
    EXPECT_NO_THROW(bus.emit(Tick{0}));  // the newly added handler runs on the NEXT emit
    bus.emit(Tick{0});
    EXPECT_GE(calls.load(), 3);
}

namespace {
struct Greeter { virtual const char* hello() const = 0; virtual ~Greeter() = default; };
struct Counter { virtual int value() const = 0; virtual ~Counter() = default; };
struct EnGreeter final : Greeter { const char* hello() const override { return "hi"; } };
struct FortyTwo  final : Counter { int value() const override { return 42; } };
}  // namespace

// Resolve a provider by interface; absent providers resolve to nullptr; interfaces
// are kept distinct; a later provide replaces the earlier one.
TEST(ServiceRegistryTest, ProvideResolveReplace) {
    ServiceRegistry reg;
    EXPECT_EQ(reg.get<Greeter>(), nullptr);  // nothing registered yet

    EnGreeter g;
    FortyTwo c;
    reg.provide<Greeter>(&g);
    reg.provide<Counter>(&c);

    ASSERT_EQ(reg.get<Greeter>(), &g);
    ASSERT_EQ(reg.get<Counter>(), &c);
    EXPECT_STREQ(reg.get<Greeter>()->hello(), "hi");
    EXPECT_EQ(reg.get<Counter>()->value(), 42);

    EnGreeter g2;
    reg.provide<Greeter>(&g2);                 // replace
    EXPECT_EQ(reg.get<Greeter>(), &g2);
}

// The Node exposes its EventBus; a NetworkChanged emitted on it reaches subscribers
// (this is the path the NetworkMonitor drives, and that subsystems subscribe to).
TEST(NodeCoordinationTest, EventsAccessorDeliversNetworkChanged) {
    NodeConfig cfg;
    cfg.enable_listen = false;
    cfg.enable_network_monitor = false;  // we emit by hand; no real monitor needed
    Node node(std::move(cfg));

    std::vector<std::string> got;
    node.events().on<NetworkChanged>([&](const NetworkChanged& e) { got = e.local_addresses; });

    node.events().emit(NetworkChanged{{"10.0.0.5", "192.168.1.20"}});
    EXPECT_EQ(got, (std::vector<std::string>{"10.0.0.5", "192.168.1.20"}));
}
