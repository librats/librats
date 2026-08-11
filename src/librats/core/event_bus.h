#pragma once

/**
 * @file event_bus.h
 * @brief A tiny typed publish/subscribe hub for decoupled module notifications.
 *
 * The "something happened" half of inter-module communication: a publisher emits
 * an event *value* and every subscriber registered for that event type is invoked.
 * The publisher neither knows nor names its subscribers — which is exactly what
 * keeps modules from acquiring direct references to one another (the road back to
 * a god-class). For the "do X / give me Y" half — a targeted call with a return
 * value — use ServiceRegistry instead.
 *
 * An event type is any value type; subscription and dispatch are keyed by it:
 *
 *     struct NetworkChanged { std::vector<std::string> addresses; };
 *     bus.on<NetworkChanged>([](const NetworkChanged& e){ ... });   // subscribe
 *     bus.emit(NetworkChanged{addrs});                              // publish → all handlers
 *
 * Threading: handlers run synchronously on the thread that calls emit(). The bus
 * itself is thread-safe (on/emit may be called concurrently), but a handler must
 * not block that thread for long — if emit() is driven from a latency-sensitive
 * thread, offload slow work. emit() snapshots the handler list under the lock and
 * invokes it unlocked, so a handler may itself emit() or on() without deadlocking.
 *
 * Convention: subscribe during a subsystem's attach() (single-threaded, before any
 * reactor runs), the same "configure before start" rule the rest of the node uses.
 */

#include <functional>
#include <mutex>
#include <typeindex>
#include <typeinfo>
#include <unordered_map>
#include <utility>
#include <vector>

namespace librats {

class EventBus {
public:
    /// Register a handler for events of type E. Additive: multiple handlers may
    /// coexist and all fire (in registration order) for each emitted event.
    template <class E>
    void on(std::function<void(const E&)> handler) {
        std::lock_guard<std::mutex> lock(mutex_);
        handlers_[std::type_index(typeid(E))].push_back(
            [h = std::move(handler)](const void* e) { h(*static_cast<const E*>(e)); });
    }

    /// Publish an event to every handler registered for its type.
    template <class E>
    void emit(const E& event) {
        std::vector<ErasedHandler> snapshot;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = handlers_.find(std::type_index(typeid(E)));
            if (it == handlers_.end()) return;
            snapshot = it->second;  // copy under lock, then invoke unlocked
        }
        for (auto& h : snapshot) h(&event);
    }

private:
    using ErasedHandler = std::function<void(const void*)>;
    std::mutex mutex_;
    std::unordered_map<std::type_index, std::vector<ErasedHandler>> handlers_;
};

} // namespace librats
