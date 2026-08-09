#include "librats/node/dialer.h"
#include "librats/util/logger.h"

#include <algorithm>
#include <utility>

namespace librats {

namespace {

/// The PeerTransports bit standing for one transport.
uint8_t mask_for(TransportKind kind) noexcept {
    return kind == TransportKind::Udp ? PeerTransportUdp : PeerTransportTcp;
}

} // namespace

std::vector<TransportKind> Dialer::transport_order(uint8_t known) const {
    const TransportKind first  = policy_.preferred;
    const TransportKind second = first == TransportKind::Udp ? TransportKind::Tcp
                                                             : TransportKind::Udp;
    const auto allowed = [this](TransportKind k) {
        return k == TransportKind::Udp ? policy_.allow_udp : policy_.allow_tcp;
    };

    std::vector<TransportKind> order;
    if (allowed(first)) order.push_back(first);
    // A zero fallback delay means "the preferred transport or nothing" — the
    // second entry is exactly what the fallback timer would bring in.
    if (allowed(second) && policy_.fallback_delay.count() > 0) order.push_back(second);
    // ...unless the preferred one is not available at all, in which case the other
    // is not a fallback, it is the only way out.
    if (order.empty() && allowed(second)) order.push_back(second);

    // A peer at this address has already told us which wires it accepts. Bring
    // those to the front — stably, so the policy still decides between two the
    // peer accepts equally. Nothing is dropped: the knowledge can be stale, and
    // the cost of acting on a stale entry must stay "one fallback delay", never
    // "this target is undialable". A single-entry order is left alone, which is
    // what keeps a zero fallback delay meaning exactly what it says.
    if (known != PeerTransportNone && order.size() > 1) {
        std::stable_partition(order.begin(), order.end(), [known](TransportKind k) {
            return (known & mask_for(k)) != 0;
        });
    }
    return order;
}

void Dialer::dial(const std::string& host, uint16_t port) {
    auto target  = std::make_shared<Target>();
    target->host = host;
    target->port = port;

    bool started = false;
    bool empty   = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopped_) return;
        // Under the lock: the order depends on what identify has taught us about
        // this address, which lives behind the same mutex as the bookkeeping.
        target->pending = transport_order(recall(host, port));
        empty           = target->pending.empty();
        if (!empty) started = start_next(target);
    }

    if (empty) LOG_WARN("dialer", "No transport enabled; cannot dial " << host << ":" << port);

    // Never with the lock held: a failure handler may well dial again (that is
    // what a reconnection policy does), and this mutex is not recursive.
    if (!started) on_failed_(host, port);
}

// ── What identify taught us about an address ────────────────────────────────

std::string Dialer::key_for(const std::string& host, uint16_t port) {
    return host + ":" + std::to_string(port);
}

uint8_t Dialer::recall(const std::string& host, uint16_t port) const {
    const auto it = known_.find(key_for(host, port));
    if (it == known_.end()) return PeerTransportNone;
    if (Clock::now() - it->second.learned_at > kMemoryTtl) return PeerTransportNone;
    return it->second.transports;
}

void Dialer::evict_one(Clock::time_point now) {
    // One pass, and only when the cache is full: drop everything that has expired,
    // and note the oldest survivor in case nothing had. A map capped at
    // kMaxRemembered makes this bounded work on a path that runs once per dial.
    auto oldest = known_.end();
    for (auto it = known_.begin(); it != known_.end();) {
        if (now - it->second.learned_at > kMemoryTtl) {
            it = known_.erase(it);
            continue;
        }
        if (oldest == known_.end() || it->second.learned_at < oldest->second.learned_at)
            oldest = it;
        ++it;
    }
    if (known_.size() >= kMaxRemembered && oldest != known_.end()) known_.erase(oldest);
}

void Dialer::remember(const std::string& host, uint16_t port, uint8_t transports) {
    // 0 is "the peer did not say" (an older node predating the field), not
    // "supports nothing" — storing it would teach us the opposite of the truth.
    if (transports == PeerTransportNone || port == 0 || host.empty()) return;

    const auto now = Clock::now();
    std::lock_guard<std::mutex> lock(mutex_);

    std::string key = key_for(host, port);
    const auto  it  = known_.find(key);
    if (it != known_.end()) {
        it->second.transports = transports;
        it->second.learned_at = now;
        return;
    }

    if (known_.size() >= kMaxRemembered) evict_one(now);
    known_.emplace(std::move(key), Known{transports, now});
}

uint8_t Dialer::known_transports(const std::string& host, uint16_t port) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return recall(host, port);
}

std::vector<TransportKind> Dialer::planned_order(const std::string& host, uint16_t port) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return transport_order(recall(host, port));
}

bool Dialer::start_next(const std::shared_ptr<Target>& target) {
    // Walk the queue rather than taking only its head: a transport the pool cannot
    // provide (no UDP socket, say) never becomes an attempt, so the next one takes
    // its place at once instead of waiting out a fallback delay for nothing.
    while (!target->pending.empty()) {
        const TransportKind kind = target->pending.front();
        target->pending.erase(target->pending.begin());

        Reactor&     reactor = reactors_.pick(kind);
        const ConnId id      = reactor.connect(target->host, target->port, kind);
        if (id == kInvalidConnId) continue;

        const PeerRoute route{reactor.index(), id};
        target->routes.push_back(route);
        attempts_.emplace(Key{route.reactor, route.conn}, target);
        LOG_DEBUG("dialer", "Dialing " << target->host << ":" << target->port
                  << " over " << to_string(kind));

        if (!target->pending.empty()) arm_fallback(target, reactor);
        return true;
    }
    return false;
}

void Dialer::arm_fallback(const std::shared_ptr<Target>& target, Reactor& reactor) {
    // The timer holds only a weak reference and re-checks the target when it
    // fires, so there is nothing to cancel when the race is decided early: the
    // target is either gone or marked won, and the timer quietly does nothing.
    std::weak_ptr<Target> weak  = target;
    const auto            delay = policy_.fallback_delay;
    Reactor*              r     = &reactor;

    r->execute([this, r, weak, delay] {
        r->schedule(delay, [this, weak] {
            auto target = weak.lock();
            if (!target) return;

            bool        failed = false;
            std::string host;
            uint16_t    port = 0;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stopped_ || target->won || target->pending.empty()) return;
                LOG_DEBUG("dialer", "Racing the fallback transport for "
                          << target->host << ":" << target->port);
                if (!start_next(target) && target->routes.empty()) {
                    failed = true;
                    host   = target->host;
                    port   = target->port;
                }
            }
            if (failed) on_failed_(host, port);
        });
    });
}

void Dialer::on_established(PeerRoute route) {
    std::vector<PeerRoute> superseded;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = attempts_.find(Key{route.reactor, route.conn});
        if (it == attempts_.end()) return;  // inbound, or a dial already settled

        std::shared_ptr<Target> target = it->second;
        target->won = true;
        target->pending.clear();

        for (const PeerRoute& other : target->routes) {
            attempts_.erase(Key{other.reactor, other.conn});
            if (other != route) superseded.push_back(other);
        }
        target->routes.clear();
    }

    // Outside the lock: close() posts to a reactor, and on this thread it may run
    // the teardown — and therefore on_closed() — straight away.
    for (const PeerRoute& other : superseded)
        reactors_.by_index(other.reactor).close(other.conn, CloseReason::DialSuperseded);
}

void Dialer::on_closed(PeerRoute route) {
    bool        failed = false;
    std::string host;
    uint16_t    port = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = attempts_.find(Key{route.reactor, route.conn});
        if (it == attempts_.end()) return;

        std::shared_ptr<Target> target = it->second;
        attempts_.erase(it);
        target->routes.erase(std::remove(target->routes.begin(), target->routes.end(), route),
                             target->routes.end());
        if (stopped_ || target->won) return;

        // This attempt is out. Bring the next transport in now rather than waiting
        // for the fallback timer: a transport that fails fast should not cost the
        // full delay before the other one is even tried.
        if (!start_next(target) && target->routes.empty()) {
            failed = true;
            host   = target->host;
            port   = target->port;
        }
    }
    if (failed) on_failed_(host, port);
}

void Dialer::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    stopped_ = false;
    attempts_.clear();  // nothing from a previous run survives a restart
}

void Dialer::stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    stopped_ = true;
    attempts_.clear();
}

size_t Dialer::in_flight() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return attempts_.size();
}

} // namespace librats
