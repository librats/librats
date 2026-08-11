#pragma once

/**
 * @file service_registry.h
 * @brief Interface-keyed service lookup for targeted, synchronous module calls.
 *
 * The "do X / give me Y" half of inter-module communication, complementing
 * EventBus (which is the fire-and-forget "something happened" half). A module
 * publishes itself under a narrow capability *interface*; another module resolves
 * that interface and calls it directly — with a return value, one-to-one — yet
 * never depends on the concrete type. Resolve returns nullptr when no provider is
 * present, so callers degrade gracefully when a module is disabled:
 *
 *     struct PublicAddressSink {                       // a narrow capability
 *         virtual void set_external_ip(const std::string&) = 0;
 *         virtual void reannounce() = 0;
 *         virtual ~PublicAddressSink() = default;
 *     };
 *     // provider (e.g. DhtDiscovery) registers itself, by interface, in attach():
 *     ctx.services.provide<PublicAddressSink>(this);
 *     // consumer resolves and calls — or does nothing if the provider is absent:
 *     if (auto* sink = ctx.services.get<PublicAddressSink>()) sink->reannounce();
 *
 * Pointers are NON-owning: the registry never extends a provider's lifetime; the
 * Node owns every module and outlives the registrations. Register exactly once per
 * interface during attach() (a later provide<I> replaces the earlier one).
 *
 * Threading: provide()/get() are not synchronized — the contract is to provide()
 * during attach() (single-threaded, before start) and get() afterwards, so reads
 * never race writes. Prefer the EventBus when there is no return value or recipient.
 */

#include <typeindex>
#include <typeinfo>
#include <unordered_map>

namespace librats {

class ServiceRegistry {
public:
    /// Register `service` as the provider of interface I (call during attach()).
    template <class I>
    void provide(I* service) {
        services_[std::type_index(typeid(I))] = static_cast<void*>(service);
    }

    /// Resolve the provider of interface I, or nullptr if none is registered.
    template <class I>
    I* get() const {
        auto it = services_.find(std::type_index(typeid(I)));
        return it == services_.end() ? nullptr : static_cast<I*>(it->second);
    }

private:
    std::unordered_map<std::type_index, void*> services_;
};

} // namespace librats
