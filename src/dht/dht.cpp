#include "dht/dht.h"
#include "dht/node.h"
#include "dht/udp_transport.h"
#include "dht/dht_runner.h"
#include "dht/persistence.h"
#include "dht/bep42.h"
#include "dht/log.h"
#include "util/network_utils.h"
#include "util/fs.h"

#include <atomic>
#include <future>
#include <random>
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

    // Run `f` on the loop thread and return its result (used by getters).
    template <class F>
    auto on_loop(F&& f) -> decltype(f()) {
        using R = decltype(f());
        std::promise<R> p;
        auto fut = p.get_future();
        runner->post([&] { p.set_value(f()); });
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
    // Node directly — no on_loop() round-trip (which would deadlock from this thread).
    // Only when a data dir is configured, to avoid littering the CWD.
    if (!impl_->data_directory.empty() && impl_->data_directory != ".") {
        impl_->runner->set_periodic(kAutosaveInterval, [this] {
            if (!impl_->node) return;
            const auto contacts = impl_->node->routing_table().good_contacts();
            write_routing_table(routing_table_file_path(), impl_->data_directory,
                                impl_->node->self(), contacts);
            LOG_DEBUG("dht", "autosaved " << contacts.size() << " contact(s)");
        });
    }

    impl_->runner->start();
    impl_->running.store(true);
    LOG_INFO("dht", "started, node " << dht::short_hex(impl_->self) << ", "
                    << (impl_->ipv6 ? "IPv6" : "IPv4") << " on port " << impl_->port);
    return true;
}

void DhtClient::stop() {
    if (!impl_->running.exchange(false)) return;
    LOG_INFO("dht", "stopping");
    if (impl_->runner) impl_->runner->stop();  // join the loop thread first

    // Single-threaded again: persist (only when a data dir is configured, to avoid
    // littering) directly from the idle node.
    if (impl_->node && !impl_->data_directory.empty()) {
        const std::size_t n = impl_->node->routing_table().good_contacts().size();
        save_routing_table();
        LOG_INFO("dht", "saved " << n << " contact(s) to disk");
    }

    impl_->runner.reset();
    impl_->node.reset();
    impl_->transport.reset();
    LOG_INFO("dht", "stopped");
}

void DhtClient::shutdown_immediate() { stop(); }

bool DhtClient::is_running() const { return impl_->running.load(); }

uint16_t DhtClient::get_port() const {
    return impl_->transport ? impl_->transport->port() : 0;
}

bool DhtClient::bootstrap(const std::vector<Address>& bootstrap_nodes) {
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
    if (!impl_->running.load()) return false;
    // A user callback runs on the loop thread, so a throw would take the whole DHT
    // down — isolate it here.
    auto safe = [](PeerDiscoveryCallback cb, const std::vector<Address>& p, const InfoHash& h) {
        if (!cb) return;
        try { cb(p, h); } catch (...) {}
    };
    impl_->runner->post([this, info_hash, callback, safe] {
        impl_->node->find_peers(
            info_hash,
            [callback, info_hash, safe](const std::vector<Address>& p) { safe(callback, p, info_hash); },
            [callback, info_hash, safe](const std::vector<Address>& all) { safe(callback, all, info_hash); },
            Impl::now());
    });
    return true;
}

bool DhtClient::announce_peer(const InfoHash& info_hash, uint16_t port, PeerDiscoveryCallback callback) {
    if (!impl_->running.load()) return false;
    const uint16_t dht_port = impl_->transport->port();
    const uint16_t announce_port = port == 0 ? dht_port : port;
    const bool implied = (announce_port == dht_port);
    impl_->runner->post([this, info_hash, announce_port, implied, callback] {
        impl_->node->announce_peer(
            info_hash, announce_port, implied,
            [callback, info_hash](const std::vector<Address>& all) {
                if (callback) try { callback(all, info_hash); } catch (...) {}
            },
            Impl::now());
    });
    return true;
}

void DhtClient::cancel_search(const InfoHash& info_hash) {
    if (!impl_->running.load()) return;
    impl_->runner->post([this, info_hash] { impl_->node->cancel_lookup(info_hash); });
}

NodeId DhtClient::get_node_id() const {
    if (impl_->running.load()) return impl_->on_loop([this] { return impl_->node->self(); });
    return impl_->self;
}

void DhtClient::set_external_ip(const std::string& ip) {
    if (impl_->running.load()) {
        impl_->runner->post([this, ip] { impl_->node->set_external_ip(ip); });
        return;
    }
    // Before start: apply BEP 42 to the cached identity so get_node_id() reflects it
    // and the node adopts it at start.
    if (!dht::is_public_address(ip)) return;
    if (network_utils::is_valid_ipv6(ip) != impl_->ipv6) return;
    impl_->external_address = ip;
    if (dht::verify_node_id_for_ip(impl_->self, ip)) return;
    std::mt19937 gen(std::random_device{}());
    NodeId regenerated;
    if (dht::generate_node_id_from_ip(ip, regenerated, gen)) {
        impl_->self = regenerated;
        LOG_INFO("dht", "external IP " << ip << " set before start, node id → "
                        << dht::short_hex(impl_->self));
    }
}

std::string DhtClient::get_external_address() const {
    if (impl_->running.load()) return impl_->on_loop([this] { return impl_->node->external_address(); });
    return impl_->external_address;
}

bool DhtClient::generate_node_id_from_ip(const std::string& ip, NodeId& out, std::mt19937& gen) {
    return dht::generate_node_id_from_ip(ip, out, gen);
}

bool DhtClient::verify_node_id_for_ip(const NodeId& id, const std::string& ip) {
    return dht::verify_node_id_for_ip(id, ip);
}

std::vector<Address> DhtClient::get_default_bootstrap_nodes() {
    return dht::Node::default_bootstrap_nodes();
}

size_t DhtClient::get_routing_table_size() const {
    if (!impl_->running.load()) return 0;
    return impl_->on_loop([this] { return impl_->node->routing_table().size(); });
}


bool DhtClient::is_search_active(const InfoHash& info_hash) const {
    if (!impl_->running.load()) return false;
    return impl_->on_loop([this, info_hash] { return impl_->node->lookup_active(info_hash, false); });
}

bool DhtClient::is_announce_active(const InfoHash& info_hash) const {
    if (!impl_->running.load()) return false;
    return impl_->on_loop([this, info_hash] { return impl_->node->lookup_active(info_hash, true); });
}

size_t DhtClient::get_active_searches_count() const {
    if (!impl_->running.load()) return 0;
    return impl_->on_loop([this] { return impl_->node->lookup_count(false); });
}

size_t DhtClient::get_active_announces_count() const {
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
    if (impl_->running.load()) impl_->node->set_spider_mode(enable);  // atomic flag, loop-safe
}
bool DhtClient::is_spider_mode() const {
    return impl_->running.load() && impl_->node->is_spider_mode();  // atomic read, loop-safe
}
void DhtClient::set_spider_announce_callback(SpiderAnnounceCallback callback) {
    if (impl_->running.load())
        impl_->runner->post([this, callback]() mutable { impl_->node->set_spider_announce_callback(std::move(callback)); });
}
void DhtClient::set_spider_ignore(bool ignore) {
    if (impl_->running.load()) impl_->node->set_spider_ignore(ignore);  // atomic
}
bool DhtClient::is_spider_ignoring() const {
    return impl_->running.load() && impl_->node->is_spider_ignoring();
}
void DhtClient::spider_walk() {
    if (impl_->running.load()) impl_->runner->post([this] { impl_->node->spider_walk(Impl::now()); });
}
size_t DhtClient::get_spider_pool_size() const {
    if (!impl_->running.load()) return 0;
    return impl_->on_loop([this] { return impl_->node->spider_pool_size(); });
}
size_t DhtClient::get_spider_visited_count() const {
    if (!impl_->running.load()) return 0;
    return impl_->on_loop([this] { return impl_->node->spider_visited_count(); });
}
void DhtClient::clear_spider_state() {
    if (impl_->running.load()) impl_->runner->post([this] { impl_->node->clear_spider_state(); });
}
#endif // RATS_SEARCH_FEATURES

std::vector<Address> resolve_bootstrap_nodes(const std::vector<Address>& nodes, bool ipv6) {
    std::vector<Address> out;
    out.reserve(nodes.size());
    for (const auto& n : nodes) {
        if (n.ip.empty() || n.port == 0) continue;

        // Numeric literal: keep it only if it belongs to this node's family.
        if (network_utils::is_valid_ipv6(n.ip)) {
            if (ipv6) out.push_back(n);
            continue;
        }
        if (network_utils::is_valid_ipv4(n.ip)) {
            if (!ipv6) out.push_back(n);
            continue;
        }

        // Hostname: resolve to our family (A for IPv4, AAAA for IPv6). Drop it if it
        // has no record there, rather than feed the engine an unmatchable hostname.
        const std::string ip = ipv6 ? network_utils::resolve_hostname_v6(n.ip)
                                    : network_utils::resolve_hostname(n.ip);
        if (!ip.empty()) out.emplace_back(ip, n.port);
    }
    return out;
}

// ---- node id -> hex (for logging) ------------------------------------------
std::string node_id_to_hex(const NodeId& id) { return dht::to_hex(id); }

} // namespace librats
