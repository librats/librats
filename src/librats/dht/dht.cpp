#include "librats/dht/dht.h"
#include "librats/dht/node.h"
#include "librats/dht/udp_transport.h"
#include "librats/dht/dht_runner.h"
#include "librats/dht/persistence.h"
#include "librats/dht/bep42.h"
#include "librats/dht/log.h"
#include "librats/util/network_utils.h"
#include "librats/util/fs.h"

#include <atomic>
#include <future>
#include <random>
#include <shared_mutex>
#include <utility>

namespace librats {

namespace {
// How often the running node flushes its routing table to disk, so a crash loses at
// most this much of the warm contact set (matches the old maintenance-loop cadence).
constexpr std::chrono::minutes kAutosaveInterval{5};

// Serialize a routing-table snapshot to `path`, creating the data dir first. Shared by
// the explicit save_routing_table() call and the periodic autosave.
bool write_routing_table(const std::string& path, const std::string& data_dir,
                         const NodeId& self, const std::vector<dht::NodeEntry>& contacts) {
    if (!data_dir.empty() && data_dir != ".")
        create_directories(data_dir.c_str());
    return dht::save_routing_table(path, self, contacts);
}

// Marks a DHT loop thread with the Impl it belongs to (null on every other thread).
// Planted from *inside* the thread at start(), so it needs no synchronisation to read
// and nothing to clear: it dies with the thread it lives on.
thread_local const void* tls_loop_owner = nullptr;
}  // namespace

// ---------------------------------------------------------------------------
// The facade owns the engine trio (transport + node + runner) and marshals every
// public call onto the runner's loop thread, where the lock-free Node lives.
// ---------------------------------------------------------------------------
struct DhtClient::Impl {
    int           port = 0;
    std::string   bind_address;
    std::string   data_directory;
    AddressFamily family = AddressFamily::IPv4;
    bool          ipv6 = false;
    NodeId        self{};               // authoritative once the node exists; cached otherwise
    std::string   external_address;     // cached pre-start; node owns it once running
    std::atomic<bool> running{false};

    std::unique_ptr<dht::UdpTransport> transport;
    std::unique_ptr<dht::Node>         node;
    std::unique_ptr<dht::DhtRunner>    runner;

    /// Guards the *existence* of the engine trio above, which start()/stop() create and
    /// destroy while other threads are calling in. `running` alone cannot do that job: a
    /// caller that reads it as true can be descheduled and resume after stop() has already
    /// freed the runner, so the very next `runner->post()` touches a dead object (and a
    /// getter blocked on its promise would never be woken). start()/stop() take it
    /// exclusively for the whole teardown; every public call takes it shared for its whole
    /// duration — via lock_lifetime(), never directly. Teardown therefore cannot begin
    /// while a call is in flight, which is what lets on_loop() below assume the loop
    /// thread is alive and will answer it.
    mutable std::shared_mutex lifetime;

    /// True when the caller is our own runner's loop thread — see lock_lifetime(). Reads
    /// the marker start() planted on that thread rather than anything hanging off
    /// `runner`, which is precisely what stop() destroys underneath a caller that has
    /// not taken `lifetime` yet.
    bool on_loop_thread() const { return tls_loop_owner == this; }

    /// `lifetime` held shared for the caller's whole call — except on the loop thread,
    /// where it is deliberately *not* taken. A user callback runs there (peer discovery,
    /// the periodic autosave) and may legitimately call back into the facade; since
    /// stop() takes the lock exclusively and only then joins that very thread, waiting
    /// for it here would deadlock the two against each other forever. Skipping it is
    /// safe for exactly the same reason: if we are executing on the loop, the loop is
    /// alive, so stop() cannot have got past its join() to the resets below it.
    std::shared_lock<std::shared_mutex> lock_lifetime() const {
        if (on_loop_thread()) return {};
        return std::shared_lock<std::shared_mutex>(lifetime);
    }

    // Run `f` on the loop thread and return its result (used by getters). Safe to block on
    // the promise: callers hold `lifetime` shared, so stop() cannot have started and the
    // loop thread is still there to run the task.
    template <class F>
    auto on_loop(F&& f) -> decltype(f()) {
        // Already on the loop: run it here. Posting would be waiting on ourselves, and
        // `f` touches the same lock-free Node the loop would have touched for us. Only
        // this round-trip path runs inline — the commands below stay post()s, so a
        // callback can never re-enter the Node from inside one of the Node's own
        // callbacks (cancel_lookup erasing the very traversal that is calling us).
        if (on_loop_thread()) return f();
        using R = decltype(f());
        std::promise<R> p;
        auto fut = p.get_future();
        runner->post([&] { p.set_value(f()); });  // cannot fail: `lifetime` is held shared
        return fut.get();
    }

    static dht::TimePoint now() { return std::chrono::steady_clock::now(); }
};

DhtClient::DhtClient(int port, const std::string& bind_address,
                     const std::string& data_directory, AddressFamily address_family)
    : impl_(std::make_unique<Impl>()) {
    impl_->port = port;
    impl_->bind_address = bind_address;
    impl_->data_directory = data_directory;
    impl_->family = address_family;
    impl_->ipv6 = (address_family == AddressFamily::IPv6);

    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<int> b(0, 255);
    for (auto& x : impl_->self) x = static_cast<uint8_t>(b(gen));

    LOG_DEBUG("dht", "client created (" << (impl_->ipv6 ? "IPv6" : "IPv4")
                     << ", port " << impl_->port << ", data_dir '" << impl_->data_directory << "')");
}

DhtClient::~DhtClient() { stop(); }

bool DhtClient::start() {
    std::unique_lock<std::shared_mutex> lock(impl_->lifetime);
    if (impl_->running.load()) return true;

    const int requested_port = impl_->port;
    impl_->transport = std::make_unique<dht::UdpTransport>(impl_->port, impl_->bind_address, impl_->family);
    if (!impl_->transport->is_open()) {
        LOG_ERROR("dht", "failed to open " << (impl_->ipv6 ? "IPv6" : "IPv4")
                         << " UDP socket on port " << requested_port);
        impl_->transport.reset();
        return false;
    }
    impl_->port = impl_->transport->port();  // record the actual bound port
    if (requested_port > 0 && impl_->port != requested_port)
        LOG_WARN("dht", "port " << requested_port << " unavailable, bound ephemeral port " << impl_->port);

    // Restore our identity + a warm contact set if we've run here before. Only when a
    // data dir is configured: without one nothing is persisted (stop() saves under the
    // same condition), and since the file name is no longer port-unique, blindly loading
    // a cwd file would cross-contaminate unrelated ephemeral nodes sharing a directory.
    std::vector<dht::NodeEntry> contacts;
    if (!impl_->data_directory.empty()) {
        NodeId loaded = impl_->self;
        if (dht::load_routing_table(routing_table_file_path(), loaded, contacts)) {
            impl_->self = loaded;
            LOG_INFO("dht", "restored identity " << dht::short_hex(impl_->self)
                            << " and " << contacts.size() << " contact(s) from disk");
        }
    }

    impl_->node = std::make_unique<dht::Node>(*impl_->transport, impl_->self, impl_->ipv6);
    if (!contacts.empty()) impl_->node->routing_table().load_contacts(contacts);

    impl_->runner = std::make_unique<dht::DhtRunner>(*impl_->node, *impl_->transport);

    // Periodically persist the warm contact set so a crash doesn't lose it (we otherwise
    // only save on a clean stop()). Runs on the loop thread, so it reads the lock-free
    // Node directly — no on_loop() round-trip and no lock needed (see lock_lifetime()):
    // stop() joins the loop before it resets the node, so the node is alive for as long
    // as this can run. Only when a data dir is configured, to avoid littering the CWD.
    if (!impl_->data_directory.empty() && impl_->data_directory != ".") {
        impl_->runner->set_periodic(kAutosaveInterval, [this] {
            if (!impl_->node) return;
            const auto contacts = impl_->node->routing_table().good_contacts();
            write_routing_table(routing_table_file_path(), impl_->data_directory,
                                impl_->node->self(), contacts);
            LOG_DEBUG("dht", "autosaved " << contacts.size() << " contact(s)");
        });
    }

    // Mark the loop thread before anything runs on it, so a callback that calls back
    // into the facade is recognised from its very first invocation.
    impl_->runner->start([impl = impl_.get()] { tls_loop_owner = impl; });
    impl_->running.store(true);
    LOG_INFO("dht", "started, node " << dht::short_hex(impl_->self) << ", "
                    << (impl_->ipv6 ? "IPv6" : "IPv4") << " on port " << impl_->port);
    return true;
}

void DhtClient::stop() {
    // Exclusive for the whole teardown: no public call may be mid-flight while the trio
    // below is destroyed, and none may start until it is done. See Impl::lifetime. This
    // one method still may not be called *from* the loop thread — it joins that thread,
    // so it would be waiting on itself no matter how the lock behaved.
    std::unique_lock<std::shared_mutex> lock(impl_->lifetime);
    if (!impl_->running.exchange(false)) return;
    LOG_INFO("dht", "stopping");
    if (impl_->runner) impl_->runner->stop();  // join the loop thread first

    // Single-threaded again: persist (only when a data dir is configured, to avoid
    // littering) directly from the idle node. Written inline rather than through
    // save_routing_table(), which would take `lifetime` a second time and deadlock.
    if (impl_->node && !impl_->data_directory.empty()) {
        const auto contacts = impl_->node->routing_table().good_contacts();
        write_routing_table(routing_table_file_path(), impl_->data_directory,
                            impl_->node->self(), contacts);
        LOG_INFO("dht", "saved " << contacts.size() << " contact(s) to disk");
    }

    impl_->runner.reset();
    impl_->node.reset();
    impl_->transport.reset();
    LOG_INFO("dht", "stopped");
}

void DhtClient::shutdown_immediate() { stop(); }

bool DhtClient::is_running() const { return impl_->running.load(); }

uint16_t DhtClient::get_port() const {
    const auto lock = impl_->lock_lifetime();
    return impl_->transport ? impl_->transport->port() : 0;
}

bool DhtClient::bootstrap(const std::vector<HostEndpoint>& bootstrap_nodes) {
    const auto lock = impl_->lock_lifetime();
    if (!impl_->running.load()) {
        LOG_WARN("dht", "bootstrap ignored — client not running");
        return false;
    }
    // Resolve hostnames (and filter by family) before the seeds reach the engine: it
    // matches a reply's source address verbatim against the address it queried, so a
    // seed left as a hostname would have every reply dropped as a spoof. Resolution can
    // block, so do it here on the caller's thread, not on the DHT loop.
    auto resolved = resolve_bootstrap_nodes(bootstrap_nodes, impl_->ipv6);
    if (resolved.empty()) {
        LOG_WARN("dht", "bootstrap failed — no usable " << (impl_->ipv6 ? "IPv6" : "IPv4")
                        << " node(s) among " << bootstrap_nodes.size() << " seed(s)");
        return false;  // nothing usable for our family
    }
    LOG_INFO("dht", "bootstrapping via " << resolved.size() << " seed(s)");
    impl_->runner->post([this, resolved] {
        impl_->node->set_bootstrap_nodes(resolved);  // reused by spider reseed
        impl_->node->bootstrap(resolved, Impl::now());
    });
    return true;
}

bool DhtClient::find_peers(const InfoHash& info_hash, PeerDiscoveryCallback callback) {
    const auto lock = impl_->lock_lifetime();
    if (!impl_->running.load()) return false;
    // A user callback runs on the loop thread, so a throw would take the whole DHT
    // down — isolate it here.
    auto safe = [](PeerDiscoveryCallback cb, const std::vector<Address>& p, const InfoHash& h) {
        if (!cb) return;
        try { cb(p, h); } catch (...) {}
    };
    impl_->runner->post([this, info_hash, callback, safe] {
        // Dedup: callers (dht_discovery / bt_client) re-issue find_peers on a refresh
        // timer that fires far faster than a lookup completes (~25s in the wild), so
        // without this they pile up into many concurrent identical traversals hammering
        // the same nodes. If a search for this hash is already running, drop the
        // duplicate — the in-flight lookup keeps delivering peers to its subscriber.
        if (impl_->node->lookup_active(info_hash, /*announce=*/false)) {
            LOG_DEBUG("dht", "find_peers " << dht::short_hex(info_hash)
                             << " skipped — search already active");
            return;
        }
        impl_->node->find_peers(
            info_hash,
            [callback, info_hash, safe](const std::vector<Address>& p) { safe(callback, p, info_hash); },
            [callback, info_hash, safe](const std::vector<Address>& all) { safe(callback, all, info_hash); },
            Impl::now());
    });
    return true;
}

bool DhtClient::announce_peer(const InfoHash& info_hash, uint16_t port, PeerDiscoveryCallback callback) {
    const auto lock = impl_->lock_lifetime();
    if (!impl_->running.load()) return false;
    const uint16_t dht_port = impl_->transport->port();
    const uint16_t announce_port = port == 0 ? dht_port : port;
    const bool implied = (announce_port == dht_port);
    // A user callback runs on the loop thread, so a throw would take the whole DHT down —
    // isolate it (same guard as find_peers).
    auto safe = [](PeerDiscoveryCallback cb, const std::vector<Address>& p, const InfoHash& h) {
        if (!cb) return;
        try { cb(p, h); } catch (...) {}
    };
    impl_->runner->post([this, info_hash, announce_port, implied, callback, safe] {
        // Dedup, same rationale as find_peers: don't stack a second announce traversal
        // for a hash that's still announcing (one announce ran ~28s in the wild).
        if (impl_->node->lookup_active(info_hash, /*announce=*/true)) {
            LOG_DEBUG("dht", "announce " << dht::short_hex(info_hash)
                             << " skipped — announce already active");
            return;
        }
        impl_->node->announce_peer(
            info_hash, announce_port, implied,
            // Peers stream in as the announce traversal discovers them, then once more in
            // full on completion — so a caller that announces also gets peer discovery for
            // free, with no separate find_peers needed.
            [callback, info_hash, safe](const std::vector<Address>& p) { safe(callback, p, info_hash); },
            [callback, info_hash, safe](const std::vector<Address>& all) { safe(callback, all, info_hash); },
            Impl::now());
    });
    return true;
}

void DhtClient::cancel_search(const InfoHash& info_hash) {
    const auto lock = impl_->lock_lifetime();
    if (!impl_->running.load()) return;
    impl_->runner->post([this, info_hash] { impl_->node->cancel_lookup(info_hash); });
}

NodeId DhtClient::get_node_id() const {
    const auto lock = impl_->lock_lifetime();
    if (impl_->running.load()) return impl_->on_loop([this] { return impl_->node->self(); });
    return impl_->self;
}

void DhtClient::set_external_ip(const std::string& ip_str) {
    const auto lock = impl_->lock_lifetime();
    // STUN and the public API hand us a textual IP — parse once here, then the engine
    // works purely in numeric IpAddress terms (no repeated re-parsing per BEP 42 step).
    const auto ip = IpAddress::parse(ip_str);
    if (!ip) return;

    if (impl_->running.load()) {
        impl_->runner->post([this, addr = *ip] { impl_->node->set_external_ip(addr); });
        return;
    }
    // Before start: apply BEP 42 to the cached identity so get_node_id() reflects it
    // and the node adopts it at start.
    if (!dht::is_public_address(*ip)) return;
    if (ip->is_v6() != impl_->ipv6) return;
    impl_->external_address = ip_str;
    if (dht::verify_node_id_for_ip(impl_->self, *ip)) return;
    std::mt19937 gen(std::random_device{}());
    NodeId regenerated;
    if (dht::generate_node_id_from_ip(*ip, regenerated, gen)) {
        impl_->self = regenerated;
        LOG_INFO("dht", "external IP " << ip_str << " set before start, node id → "
                        << dht::short_hex(impl_->self));
    }
}

std::string DhtClient::get_external_address() const {
    const auto lock = impl_->lock_lifetime();
    if (impl_->running.load())
        return impl_->on_loop([this] { return impl_->node->external_address().to_string(); });
    return impl_->external_address;
}

bool DhtClient::verify_node_id_for_ip(const NodeId& id, const std::string& ip) {
    return dht::verify_node_id_for_ip(id, ip);
}

std::vector<HostEndpoint> DhtClient::get_default_bootstrap_nodes() {
    return dht::Node::default_bootstrap_nodes();
}

size_t DhtClient::get_routing_table_size() const {
    const auto lock = impl_->lock_lifetime();
    if (!impl_->running.load()) return 0;
    return impl_->on_loop([this] { return impl_->node->routing_table().size(); });
}


bool DhtClient::is_search_active(const InfoHash& info_hash) const {
    const auto lock = impl_->lock_lifetime();
    if (!impl_->running.load()) return false;
    return impl_->on_loop([this, info_hash] { return impl_->node->lookup_active(info_hash, false); });
}

bool DhtClient::is_announce_active(const InfoHash& info_hash) const {
    const auto lock = impl_->lock_lifetime();
    if (!impl_->running.load()) return false;
    return impl_->on_loop([this, info_hash] { return impl_->node->lookup_active(info_hash, true); });
}

size_t DhtClient::get_active_searches_count() const {
    const auto lock = impl_->lock_lifetime();
    if (!impl_->running.load()) return 0;
    return impl_->on_loop([this] { return impl_->node->lookup_count(false); });
}

size_t DhtClient::get_active_announces_count() const {
    const auto lock = impl_->lock_lifetime();
    if (!impl_->running.load()) return 0;
    return impl_->on_loop([this] { return impl_->node->lookup_count(true); });
}

AddressFamily DhtClient::address_family() const { return impl_->family; }
bool DhtClient::is_ipv6() const { return impl_->ipv6; }

std::string DhtClient::routing_table_file_path() const {
    // One routing-table file per data dir (plus the IPv6 variant). The name is
    // deliberately port-independent: an ephemeral (port 0) node binds a different port
    // each run, so a port in the name would mean it never finds its own saved identity
    // + warm set on restart.
    const char* suffix = impl_->ipv6 ? "_v6" : "";
    const std::string name = std::string("dht_routing") + suffix + ".json";
    if (!impl_->data_directory.empty() && impl_->data_directory != ".")
        return impl_->data_directory + "/" + name;
    return name;
}

bool DhtClient::save_routing_table() {
    const auto lock = impl_->lock_lifetime();
    NodeId self = impl_->self;
    std::vector<dht::NodeEntry> contacts;
    if (impl_->running.load() && impl_->node) {
        auto snap = impl_->on_loop([this] {
            return std::make_pair(impl_->node->self(), impl_->node->routing_table().good_contacts());
        });
        self = snap.first;
        contacts = std::move(snap.second);
    } else if (impl_->node) {
        self = impl_->node->self();
        contacts = impl_->node->routing_table().good_contacts();
    }
    return write_routing_table(routing_table_file_path(), impl_->data_directory, self, contacts);
}

bool DhtClient::load_routing_table() {
    const auto lock = impl_->lock_lifetime();
    NodeId loaded = impl_->self;
    std::vector<dht::NodeEntry> contacts;
    if (!dht::load_routing_table(routing_table_file_path(), loaded, contacts)) return false;
    impl_->self = loaded;
    if (impl_->running.load() && impl_->node)
        impl_->on_loop([this, &contacts] { impl_->node->routing_table().load_contacts(contacts); return 0; });
    LOG_DEBUG("dht", "loaded " << contacts.size() << " contact(s) from disk");
    return true;
}

void DhtClient::set_data_directory(const std::string& directory) { impl_->data_directory = directory; }

#ifdef RATS_SEARCH_FEATURES
void DhtClient::set_spider_mode(bool enable) {
    const auto lock = impl_->lock_lifetime();
    if (impl_->running.load()) impl_->node->set_spider_mode(enable);  // atomic flag, loop-safe
}
bool DhtClient::is_spider_mode() const {
    const auto lock = impl_->lock_lifetime();
    return impl_->running.load() && impl_->node->is_spider_mode();  // atomic read, loop-safe
}
void DhtClient::set_spider_announce_callback(SpiderAnnounceCallback callback) {
    const auto lock = impl_->lock_lifetime();
    if (impl_->running.load())
        impl_->runner->post([this, callback]() mutable { impl_->node->set_spider_announce_callback(std::move(callback)); });
}
void DhtClient::set_spider_ignore(bool ignore) {
    const auto lock = impl_->lock_lifetime();
    if (impl_->running.load()) impl_->node->set_spider_ignore(ignore);  // atomic
}
bool DhtClient::is_spider_ignoring() const {
    const auto lock = impl_->lock_lifetime();
    return impl_->running.load() && impl_->node->is_spider_ignoring();
}
void DhtClient::spider_walk() {
    const auto lock = impl_->lock_lifetime();
    if (impl_->running.load()) impl_->runner->post([this] { impl_->node->spider_walk(Impl::now()); });
}
size_t DhtClient::get_spider_pool_size() const {
    const auto lock = impl_->lock_lifetime();
    if (!impl_->running.load()) return 0;
    return impl_->on_loop([this] { return impl_->node->spider_pool_size(); });
}
size_t DhtClient::get_spider_visited_count() const {
    const auto lock = impl_->lock_lifetime();
    if (!impl_->running.load()) return 0;
    return impl_->on_loop([this] { return impl_->node->spider_visited_count(); });
}
void DhtClient::clear_spider_state() {
    const auto lock = impl_->lock_lifetime();
    if (impl_->running.load()) impl_->runner->post([this] { impl_->node->clear_spider_state(); });
}
#endif // RATS_SEARCH_FEATURES

std::vector<Address> resolve_bootstrap_nodes(const std::vector<HostEndpoint>& nodes, bool ipv6) {
    std::vector<Address> out;
    out.reserve(nodes.size());
    for (const auto& n : nodes) {
        if (n.host.empty() || n.port == 0) continue;

        // Numeric literal: keep it only if it belongs to this node's family.
        if (auto ip = IpAddress::parse(n.host)) {
            if (ip->is_v6() == ipv6) out.push_back(Address{*ip, n.port});
            continue;
        }

        // Hostname: resolve to our family (A for IPv4, AAAA for IPv6). Drop it if it
        // has no record there, rather than feed the engine an unmatchable hostname.
        const std::string ip = ipv6 ? network_utils::resolve_hostname_v6(n.host)
                                    : network_utils::resolve_hostname(n.host);
        if (auto a = IpAddress::parse(ip)) out.push_back(Address{*a, n.port});
    }
    return out;
}

// ---- node id -> hex (for logging) ------------------------------------------
std::string node_id_to_hex(const NodeId& id) { return dht::to_hex(id); }

} // namespace librats
