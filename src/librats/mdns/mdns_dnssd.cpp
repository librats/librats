#include "librats/mdns/mdns_dnssd.h"

#if defined(__APPLE__)

#include "librats/mdns/log.h"
#include "librats/util/network_utils.h"

#include <algorithm>
#include <utility>

#include <arpa/inet.h>
#include <errno.h>
#include <sys/select.h>

namespace librats {

namespace {

/// How long to wait for a browse hit to resolve before giving up on it. mDNSResponder
/// keeps a resolve open indefinitely (it is a subscription, not a query), so without a
/// deadline a peer that answered a PTR and then vanished would leak its handle.
constexpr auto kResolveTimeout = std::chrono::seconds(5);

/// dns_sd takes the service type without a domain ("_librats._tcp"), while
/// LIBRATS_SERVICE_TYPE carries the ".local." that the raw-socket backend puts on the
/// wire. Derive one from the other so the two backends cannot drift apart.
std::string dnssd_regtype() {
    std::string type = LIBRATS_SERVICE_TYPE;
    const std::string domain = "local.";
    if (type.size() > domain.size() &&
        type.compare(type.size() - domain.size(), domain.size(), domain) == 0) {
        type.erase(type.size() - domain.size());
    }
    while (!type.empty() && type.back() == '.') type.pop_back();
    return type;
}

} // namespace

DnssdMdnsClient::DnssdMdnsClient(const std::string& service_instance_name, uint16_t service_port)
    : instance_name_(service_instance_name), service_port_(service_port) {}

DnssdMdnsClient::~DnssdMdnsClient() { stop(); }

bool DnssdMdnsClient::start() {
    if (running_.exchange(true)) return true;
    thread_ = std::thread([this] { loop(); });
    return true;
}

void DnssdMdnsClient::stop() {
    if (!running_.exchange(false)) return;
    {
        std::lock_guard<std::mutex> lock(request_mutex_);
        want_announce_ = false;
        want_discovery_ = false;
    }
    wakeup_.signal();
    if (thread_.joinable()) thread_.join();
    announcing_.store(false);
    discovering_.store(false);
}

void DnssdMdnsClient::set_service_callback(MdnsServiceCallback callback) {
    // Set before start(), like the raw-socket backend: the worker thread reads it
    // without a lock, which is only sound because it never changes once running.
    service_callback_ = std::move(callback);
}

bool DnssdMdnsClient::announce_service(const std::string& instance_name, uint16_t port) {
    {
        std::lock_guard<std::mutex> lock(request_mutex_);
        want_announce_ = true;
        announce_name_ = instance_name.empty() ? instance_name_ : instance_name;
        announce_port_ = port != 0 ? port : service_port_;
    }
    wakeup_.signal();
    return true;
}

void DnssdMdnsClient::stop_announcing() {
    {
        std::lock_guard<std::mutex> lock(request_mutex_);
        want_announce_ = false;
    }
    wakeup_.signal();
}

bool DnssdMdnsClient::start_discovery() {
    {
        std::lock_guard<std::mutex> lock(request_mutex_);
        want_discovery_ = true;
    }
    wakeup_.signal();
    return true;
}

void DnssdMdnsClient::stop_discovery() {
    {
        std::lock_guard<std::mutex> lock(request_mutex_);
        want_discovery_ = false;
    }
    wakeup_.signal();
}

void DnssdMdnsClient::loop() {
    while (running_.load()) {
        reconcile();
        start_resolves();

        fd_set read_set;
        FD_ZERO(&read_set);
        int max_fd = -1;
        const auto watch = [&](int fd) {
            if (fd < 0) return;
            FD_SET(fd, &read_set);
            max_fd = std::max(max_fd, fd);
        };

        const socket_t wake_fd = wakeup_.fd();
        if (is_valid_socket(wake_fd)) watch(static_cast<int>(wake_fd));
        if (register_ref_ != nullptr) watch(DNSServiceRefSockFD(register_ref_));
        if (browse_ref_ != nullptr)   watch(DNSServiceRefSockFD(browse_ref_));
        for (const auto& resolve : resolves_) {
            if (resolve.ref != nullptr && !resolve.finished) watch(DNSServiceRefSockFD(resolve.ref));
        }

        // A one-second cap rather than an indefinite wait, so a resolve deadline is
        // still reaped on a silent network. Anything urgent signals the wakeup pipe.
        timeval timeout{1, 0};
        const int ready = select(max_fd + 1, &read_set, nullptr, nullptr, &timeout);
        if (!running_.load()) break;

        if (ready < 0) {
            if (errno == EINTR) continue;
            LOG_MDNS_ERROR("mDNS select failed: errno " << errno);
            // Do not spin on a persistent failure; the 1s timeout above no longer
            // paces the loop once select() is returning immediately.
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        if (ready > 0) {
            if (is_valid_socket(wake_fd) && FD_ISSET(wake_fd, &read_set)) wakeup_.drain();

            if (register_ref_ != nullptr) {
                const int fd = DNSServiceRefSockFD(register_ref_);
                if (fd >= 0 && FD_ISSET(fd, &read_set) &&
                    DNSServiceProcessResult(register_ref_) != kDNSServiceErr_NoError) {
                    LOG_MDNS_WARN("mDNS registration dropped; will not re-announce");
                    DNSServiceRefDeallocate(register_ref_);
                    register_ref_ = nullptr;
                    announcing_.store(false);
                    std::lock_guard<std::mutex> lock(request_mutex_);
                    want_announce_ = false;
                }
            }

            if (browse_ref_ != nullptr) {
                const int fd = DNSServiceRefSockFD(browse_ref_);
                if (fd >= 0 && FD_ISSET(fd, &read_set) &&
                    DNSServiceProcessResult(browse_ref_) != kDNSServiceErr_NoError) {
                    LOG_MDNS_WARN("mDNS browse dropped; discovery has stopped");
                    DNSServiceRefDeallocate(browse_ref_);
                    browse_ref_ = nullptr;
                    discovering_.store(false);
                    std::lock_guard<std::mutex> lock(request_mutex_);
                    want_discovery_ = false;
                }
            }

            // Indexed rather than range-based: on_resolve() writes through to
            // resolves_[i].finished, and reaping happens afterwards, not here.
            for (size_t i = 0; i < resolves_.size(); ++i) {
                Resolve& resolve = resolves_[i];
                if (resolve.ref == nullptr || resolve.finished) continue;
                const int fd = DNSServiceRefSockFD(resolve.ref);
                if (fd < 0 || !FD_ISSET(fd, &read_set)) continue;
                if (DNSServiceProcessResult(resolve.ref) != kDNSServiceErr_NoError) {
                    resolve.finished = true;
                }
            }
        }

        emit_resolved();
        reap_resolves(false);
    }

    teardown();
}

void DnssdMdnsClient::reconcile() {
    bool        want_announce = false;
    std::string name;
    uint16_t    port = 0;
    bool        want_discovery = false;
    {
        std::lock_guard<std::mutex> lock(request_mutex_);
        want_announce  = want_announce_;
        name           = announce_name_;
        port           = announce_port_;
        want_discovery = want_discovery_;
    }

    if (want_announce && register_ref_ == nullptr) {
        DNSServiceRef    ref = nullptr;
        const std::string type = dnssd_regtype();
        // Flags 0 (rather than kDNSServiceFlagsNoAutoRename) lets mDNSResponder rename
        // on a name clash. That is what we want: two nodes whose instance labels
        // collide should both stay advertised, and MdnsDiscovery's own-announcement
        // filter matches on the label as a substring, so a rename does not break it.
        const auto err = DNSServiceRegister(&ref, /*flags=*/0, kDNSServiceInterfaceIndexAny,
                                            name.c_str(), type.c_str(),
                                            /*domain=*/nullptr, /*host=*/nullptr,
                                            htons(port), /*txtLen=*/0, /*txtRecord=*/nullptr,
                                            &on_register, this);
        if (err == kDNSServiceErr_NoError) {
            register_ref_ = ref;
        } else {
            LOG_MDNS_ERROR("DNSServiceRegister failed: " << err);
            std::lock_guard<std::mutex> lock(request_mutex_);
            want_announce_ = false;  // don't retry every iteration
        }
    } else if (!want_announce && register_ref_ != nullptr) {
        DNSServiceRefDeallocate(register_ref_);
        register_ref_ = nullptr;
        announcing_.store(false);
    }

    if (want_discovery && browse_ref_ == nullptr) {
        DNSServiceRef     ref = nullptr;
        const std::string type = dnssd_regtype();
        const auto err = DNSServiceBrowse(&ref, /*flags=*/0, kDNSServiceInterfaceIndexAny,
                                          type.c_str(), /*domain=*/nullptr, &on_browse, this);
        if (err == kDNSServiceErr_NoError) {
            browse_ref_ = ref;
            discovering_.store(true);
            LOG_MDNS_INFO("Browsing for " << type << " via mDNSResponder");
        } else {
            LOG_MDNS_ERROR("DNSServiceBrowse failed: " << err);
            std::lock_guard<std::mutex> lock(request_mutex_);
            want_discovery_ = false;
        }
    } else if (!want_discovery && browse_ref_ != nullptr) {
        DNSServiceRefDeallocate(browse_ref_);
        browse_ref_ = nullptr;
        discovering_.store(false);
    }
}

void DnssdMdnsClient::start_resolves() {
    if (browse_hits_.empty()) return;

    std::vector<BrowseHit> hits;
    hits.swap(browse_hits_);
    for (const auto& hit : hits) {
        DNSServiceRef ref = nullptr;
        const auto err = DNSServiceResolve(&ref, /*flags=*/0, hit.interface_index,
                                           hit.name.c_str(), hit.regtype.c_str(),
                                           hit.domain.c_str(), &on_resolve, this);
        if (err != kDNSServiceErr_NoError) {
            LOG_MDNS_WARN("DNSServiceResolve failed for " << hit.name << ": " << err);
            continue;
        }
        resolves_.push_back(Resolve{ref, std::chrono::steady_clock::now() + kResolveTimeout, false});
    }
}

void DnssdMdnsClient::emit_resolved() {
    if (resolved_.empty()) return;

    std::vector<Resolved> items;
    items.swap(resolved_);
    for (const auto& item : items) {
        // Bonjour hands back a hostname; PeerNetwork needs a numeric address. On Apple
        // platforms getaddrinfo() resolves a ".local." name through mDNSResponder, which
        // avoids a second asynchronous stage (DNSServiceGetAddrInfo) for the one thing
        // still missing.
        //
        // Two caveats, both of which cost at most a failed dial and a re-announcement:
        //
        // It drops the interface the service was seen on, so on a multi-homed host the
        // address may belong to a different interface than the announcement arrived on.
        // That is why this is not strictly equivalent to DNSServiceGetAddrInfo with the
        // browse's interface index.
        //
        // And it trusts the peer's hostname to be unique, which on a LAN of Android
        // peers it is not: MdnsClient announces the host as "localhost", and it
        // implements no name-conflict defence, so two Android nodes both claim
        // "localhost.local." and a resolver gets whichever answers first. The
        // raw-socket backend sidesteps this by reading the address straight out of the
        // announcement's A record instead of resolving the name at all.
        std::string ip = network_utils::resolve_hostname(item.host);
        if (ip.empty()) ip = network_utils::resolve_hostname_v6(item.host);
        if (ip.empty()) {
            LOG_MDNS_WARN("Could not resolve " << item.host << " for " << item.full_name);
            continue;
        }

        LOG_MDNS_DEBUG("Resolved " << item.full_name << " to " << ip << ":" << item.port);
        // Always reported as new: this backend keeps no service cache, and the only
        // consumer (MdnsDiscovery) de-duplicates by address anyway.
        const MdnsService service(item.full_name, item.host, ip, item.port);
        if (service_callback_) service_callback_(service, true);
    }
}

void DnssdMdnsClient::reap_resolves(bool force) {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = resolves_.begin(); it != resolves_.end();) {
        if (force || it->finished || now >= it->deadline) {
            if (it->ref != nullptr) DNSServiceRefDeallocate(it->ref);
            it = resolves_.erase(it);
        } else {
            ++it;
        }
    }
}

void DnssdMdnsClient::teardown() {
    reap_resolves(true);
    if (register_ref_ != nullptr) {
        DNSServiceRefDeallocate(register_ref_);
        register_ref_ = nullptr;
    }
    if (browse_ref_ != nullptr) {
        DNSServiceRefDeallocate(browse_ref_);
        browse_ref_ = nullptr;
    }
    announcing_.store(false);
    discovering_.store(false);
}

// ── dns_sd callbacks ────────────────────────────────────────────────────────────
//
// All three run on the worker thread, inside DNSServiceProcessResult. They only move
// data into the queues: creating or deallocating a DNSServiceRef from inside a callback
// is not safe, so every such call is left to the loop.

void DNSSD_API DnssdMdnsClient::on_register(DNSServiceRef /*ref*/, DNSServiceFlags /*flags*/,
                                            DNSServiceErrorType error, const char* name,
                                            const char* regtype, const char* /*domain*/,
                                            void* context) {
    auto* self = static_cast<DnssdMdnsClient*>(context);
    if (self == nullptr) return;
    if (error != kDNSServiceErr_NoError) {
        LOG_MDNS_ERROR("mDNS registration failed: " << error);
        self->announcing_.store(false);
        return;
    }
    self->announcing_.store(true);
    LOG_MDNS_INFO("Registered '" << (name != nullptr ? name : "?") << "' as "
                                 << (regtype != nullptr ? regtype : "?"));
}

void DNSSD_API DnssdMdnsClient::on_browse(DNSServiceRef /*ref*/, DNSServiceFlags flags,
                                          uint32_t interface_index, DNSServiceErrorType error,
                                          const char* name, const char* regtype,
                                          const char* domain, void* context) {
    auto* self = static_cast<DnssdMdnsClient*>(context);
    if (self == nullptr) return;
    if (error != kDNSServiceErr_NoError) {
        LOG_MDNS_WARN("mDNS browse error: " << error);
        return;
    }
    // Removals are ignored: MdnsDiscovery only ever dials, and the node's own peer
    // table is what tracks whether a peer is still there.
    if ((flags & kDNSServiceFlagsAdd) == 0) return;
    if (name == nullptr || regtype == nullptr || domain == nullptr) return;

    self->browse_hits_.push_back(BrowseHit{interface_index, name, regtype, domain});
}

void DNSSD_API DnssdMdnsClient::on_resolve(DNSServiceRef ref, DNSServiceFlags /*flags*/,
                                           uint32_t /*interface_index*/, DNSServiceErrorType error,
                                           const char* full_name, const char* host, uint16_t port,
                                           uint16_t /*txt_len*/, const unsigned char* /*txt*/,
                                           void* context) {
    auto* self = static_cast<DnssdMdnsClient*>(context);
    if (self == nullptr) return;

    // Mark this resolve done either way — one answer is all we need, and the loop
    // deallocates it on the next pass.
    for (auto& resolve : self->resolves_) {
        if (resolve.ref == ref) {
            resolve.finished = true;
            break;
        }
    }

    if (error != kDNSServiceErr_NoError) {
        LOG_MDNS_WARN("mDNS resolve error: " << error);
        return;
    }
    if (full_name == nullptr || host == nullptr) return;

    self->resolved_.push_back(Resolved{full_name, host, ntohs(port)});
}

} // namespace librats

#endif // __APPLE__
