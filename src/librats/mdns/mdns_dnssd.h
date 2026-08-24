#pragma once

/**
 * @file mdns_dnssd.h
 * @brief mDNS through Bonjour (dns_sd) — the Apple-platform backend for MdnsDiscovery.
 *
 * Same job and the same wire protocol as MdnsClient, except the multicast is done by
 * the system's mDNSResponder instead of by a socket we own. That is not a stylistic
 * preference: since iOS 14 an app may only send or receive multicast *directly* if it
 * holds `com.apple.developer.networking.multicast`, an entitlement Apple grants only
 * on request, so the raw-socket path yields no discovery at all in an ordinary app.
 * Traffic routed through mDNSResponder needs no entitlement — only the
 * `NSLocalNetworkUsageDescription` and `NSBonjourServices` Info.plist keys and the
 * user's local-network consent.
 *
 * Both backends speak standard mDNS, so an Apple node and a raw-socket node (Android,
 * Linux, Windows) discover each other normally.
 *
 * dns_sd lives in libSystem on macOS and iOS alike, so this links with no extra
 * library and needs no Objective-C.
 *
 * Only the subset of MdnsClient that MdnsDiscovery actually calls is implemented —
 * the two are interchangeable through the `MdnsBackend` alias in mdns_discovery.h,
 * and anything beyond that subset is deliberately a compile error rather than a
 * silent no-op.
 *
 * Threading: every dns_sd object is created, polled and destroyed on this class's own
 * thread. Callers only set desired state (announce / discover) and signal the thread,
 * so there are no locks around the dns_sd handles at all — the same
 * post-work-to-the-owning-thread discipline the reactors use.
 */

#include "librats/core/wakeup_pipe.h"
#include "librats/mdns/mdns.h"   // MdnsService, MdnsServiceCallback, LIBRATS_SERVICE_TYPE

#if defined(__APPLE__)

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <dns_sd.h>

namespace librats {

class DnssdMdnsClient {
public:
    explicit DnssdMdnsClient(const std::string& service_instance_name = "", uint16_t service_port = 0);
    ~DnssdMdnsClient();

    DnssdMdnsClient(const DnssdMdnsClient&) = delete;
    DnssdMdnsClient& operator=(const DnssdMdnsClient&) = delete;

    bool start();
    void stop();
    bool is_running() const { return running_.load(); }

    /// Register the service with mDNSResponder. Only the port is needed — unlike the
    /// raw-socket backend this does not bind anything, so it advertises the port the
    /// node already listens on rather than a second socket.
    ///
    /// The registration happens on the worker thread, so a dns_sd failure is logged
    /// there rather than returned here; the return value only reports that the request
    /// was accepted (which is all MdnsDiscovery inspects).
    bool announce_service(const std::string& instance_name, uint16_t port);
    void stop_announcing();
    bool is_announcing() const { return announcing_.load(); }

    void set_service_callback(MdnsServiceCallback callback);
    bool start_discovery();
    void stop_discovery();
    bool is_discovering() const { return discovering_.load(); }

private:
    /// A browse hit waiting to be resolved. Held as plain data rather than as a
    /// DNSServiceRef because it is produced inside a dns_sd callback, where starting
    /// or tearing down another operation is not safe.
    struct BrowseHit {
        uint32_t    interface_index = 0;
        std::string name;
        std::string regtype;
        std::string domain;
    };

    /// An in-flight DNSServiceResolve.
    struct Resolve {
        DNSServiceRef                         ref = nullptr;
        std::chrono::steady_clock::time_point deadline;
        bool                                  finished = false;  ///< terminal callback seen; reap it
    };

    /// A resolve that produced a host and port, pending the address lookup.
    struct Resolved {
        std::string full_name;
        std::string host;
        uint16_t    port = 0;
    };

    void loop();
    void reconcile();       ///< bring the dns_sd operations in line with the desired state
    void start_resolves();  ///< turn queued browse hits into DNSServiceResolve calls
    void emit_resolved();   ///< look up addresses and hand finished services to the callback
    void reap_resolves(bool force);
    void teardown();        ///< deallocate every dns_sd handle (worker thread only)

    static void DNSSD_API on_register(DNSServiceRef ref, DNSServiceFlags flags,
                                      DNSServiceErrorType error, const char* name,
                                      const char* regtype, const char* domain, void* context);
    static void DNSSD_API on_browse(DNSServiceRef ref, DNSServiceFlags flags,
                                    uint32_t interface_index, DNSServiceErrorType error,
                                    const char* name, const char* regtype,
                                    const char* domain, void* context);
    static void DNSSD_API on_resolve(DNSServiceRef ref, DNSServiceFlags flags,
                                     uint32_t interface_index, DNSServiceErrorType error,
                                     const char* full_name, const char* host, uint16_t port,
                                     uint16_t txt_len, const unsigned char* txt, void* context);

    // — set once, before the thread starts —
    std::string        instance_name_;
    uint16_t           service_port_ = 0;
    MdnsServiceCallback service_callback_;

    // — desired state, written by callers and read by the worker —
    std::mutex  request_mutex_;
    bool        want_announce_ = false;
    std::string announce_name_;
    uint16_t    announce_port_ = 0;
    bool        want_discovery_ = false;

    std::atomic<bool> running_{false};
    std::atomic<bool> announcing_{false};
    std::atomic<bool> discovering_{false};

    // — worker-thread-only state —
    DNSServiceRef         register_ref_ = nullptr;
    DNSServiceRef         browse_ref_ = nullptr;
    std::vector<Resolve>  resolves_;

    /// Written inside dns_sd callbacks (which run on the worker thread inside
    /// DNSServiceProcessResult) and drained by the worker between polls. Same thread
    /// throughout, so no lock — the queues exist to get work *out* of the callbacks,
    /// where touching a DNSServiceRef is not allowed.
    std::vector<BrowseHit> browse_hits_;
    std::vector<Resolved>  resolved_;

    WakeupPipe  wakeup_;
    std::thread thread_;
};

} // namespace librats

#endif // __APPLE__
