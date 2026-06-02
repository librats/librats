#ifdef _WIN32
    // Include winsock2.h first to avoid conflicts with windows.h
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
#else
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>

    #ifdef RATS_ANDROID_OLD_API
        #include <ifaddrs-android.h>
    #else
        #include <ifaddrs.h>
    #endif

    // macOS / BSD default-gateway lookup via the PF_ROUTE sysctl routing table.
    #if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
        defined(__OpenBSD__) || defined(__DragonFly__)
        #define RATS_HAVE_BSD_ROUTES 1
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <sys/sysctl.h>
        #include <net/route.h>
        #include <net/if.h>
    #endif
#endif



#include "network_utils.h"
#include "logger.h"
#include <cstring>
#include <iostream>
#include <vector>
#include <algorithm>

#ifndef _WIN32
    #include <cstdio>
    #include <cstdlib>
#endif

// Network utilities module logging macros
#define LOG_NETUTILS_DEBUG(message) LOG_DEBUG("network_utils", message)
#define LOG_NETUTILS_INFO(message)  LOG_INFO("network_utils", message)
#define LOG_NETUTILS_WARN(message)  LOG_WARN("network_utils", message)
#define LOG_NETUTILS_ERROR(message) LOG_ERROR("network_utils", message)

namespace librats {
namespace network_utils {

// ── Internal helpers (not exposed in header) ────────────────────────────────

namespace {

std::vector<std::string> get_local_interface_addresses_v4() {
    LOG_NETUTILS_DEBUG("Getting local IPv4 interface addresses");
    
    std::vector<std::string> addresses;
    
#ifdef _WIN32
    DWORD dwRetVal = 0;
    ULONG outBufLen = 15000;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = nullptr;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = nullptr;
    
    do {
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (pAddresses == nullptr) {
            LOG_NETUTILS_ERROR("Memory allocation failed for GetAdaptersAddresses");
            return addresses;
        }

        dwRetVal = GetAdaptersAddresses(AF_INET, flags, nullptr, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = nullptr;
        } else {
            break;
        }
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (outBufLen < 65535));

    if (dwRetVal == NO_ERROR) {
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            pUnicast = pCurrAddresses->FirstUnicastAddress;
            while (pUnicast != nullptr) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET) {
                    sockaddr_in* sockaddr_ipv4 = (sockaddr_in*)pUnicast->Address.lpSockaddr;
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sockaddr_ipv4->sin_addr, ip_str, INET_ADDRSTRLEN);
                    std::string ip_address(ip_str);
                    addresses.push_back(ip_address);
                    LOG_NETUTILS_DEBUG("Found local IPv4 address: " << ip_address);
                }
                pUnicast = pUnicast->Next;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    } else {
        LOG_NETUTILS_ERROR("GetAdaptersAddresses failed with error: " << dwRetVal);
    }

    if (pAddresses) {
        free(pAddresses);
    }

#else
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        LOG_NETUTILS_ERROR("getifaddrs failed");
        return addresses;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            char ip_str[INET_ADDRSTRLEN];
            struct sockaddr_in* addr_in = (struct sockaddr_in*)ifa->ifa_addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
            std::string ip_address(ip_str);
            addresses.push_back(ip_address);
            LOG_NETUTILS_DEBUG("Found local IPv4 address: " << ip_address << " on interface " << ifa->ifa_name);
        }
    }

    freeifaddrs(ifaddr);
#endif
    
    LOG_NETUTILS_INFO("Found " << addresses.size() << " local IPv4 addresses");
    return addresses;
}

std::vector<std::string> get_local_interface_addresses_v6() {
    LOG_NETUTILS_DEBUG("Getting local IPv6 interface addresses");
    
    std::vector<std::string> addresses;
    
#ifdef _WIN32
    DWORD dwRetVal = 0;
    ULONG outBufLen = 15000;
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    
    PIP_ADAPTER_ADDRESSES pAddresses = nullptr;
    PIP_ADAPTER_ADDRESSES pCurrAddresses = nullptr;
    PIP_ADAPTER_UNICAST_ADDRESS pUnicast = nullptr;
    
    do {
        pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (pAddresses == nullptr) {
            LOG_NETUTILS_ERROR("Memory allocation failed for GetAdaptersAddresses");
            return addresses;
        }

        dwRetVal = GetAdaptersAddresses(AF_INET6, flags, nullptr, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            free(pAddresses);
            pAddresses = nullptr;
        } else {
            break;
        }
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (outBufLen < 65535));

    if (dwRetVal == NO_ERROR) {
        pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            pUnicast = pCurrAddresses->FirstUnicastAddress;
            while (pUnicast != nullptr) {
                if (pUnicast->Address.lpSockaddr->sa_family == AF_INET6) {
                    sockaddr_in6* sockaddr_ipv6 = (sockaddr_in6*)pUnicast->Address.lpSockaddr;
                    char ip_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &sockaddr_ipv6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
                    std::string ip_address(ip_str);
                    addresses.push_back(ip_address);
                    LOG_NETUTILS_DEBUG("Found local IPv6 address: " << ip_address);
                }
                pUnicast = pUnicast->Next;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }
    } else {
        LOG_NETUTILS_ERROR("GetAdaptersAddresses failed with error: " << dwRetVal);
    }

    if (pAddresses) {
        free(pAddresses);
    }

#else
    struct ifaddrs *ifaddr, *ifa;
    
    if (getifaddrs(&ifaddr) == -1) {
        LOG_NETUTILS_ERROR("getifaddrs failed");
        return addresses;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET6) {
            char ip_str[INET6_ADDRSTRLEN];
            struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)ifa->ifa_addr;
            inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
            std::string ip_address(ip_str);
            addresses.push_back(ip_address);
            LOG_NETUTILS_DEBUG("Found local IPv6 address: " << ip_address << " on interface " << ifa->ifa_name);
        }
    }

    freeifaddrs(ifaddr);
#endif
    
    LOG_NETUTILS_INFO("Found " << addresses.size() << " local IPv6 addresses");
    return addresses;
}

} // anonymous namespace

// ── Public API ──────────────────────────────────────────────────────────────

std::string resolve_hostname(const std::string& hostname) {
    LOG_NETUTILS_DEBUG("Resolving hostname: " << hostname);
    
    if (hostname.empty()) {
        LOG_NETUTILS_DEBUG("Empty hostname provided");
        return "";
    }
    
    if (is_valid_ipv4(hostname)) {
        LOG_NETUTILS_DEBUG("Already an IP address: " << hostname);
        return hostname;
    }
    
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (status != 0) {
#ifdef _WIN32
        LOG_NETUTILS_ERROR("Failed to resolve hostname " << hostname << ": " << WSAGetLastError());
#else
        LOG_NETUTILS_ERROR("Failed to resolve hostname " << hostname << ": " << gai_strerror(status));
#endif
        return "";
    }
    
    char ip_str[INET_ADDRSTRLEN];
    struct sockaddr_in* addr_in = (struct sockaddr_in*)result->ai_addr;
    inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
    
    freeaddrinfo(result);
    
    LOG_NETUTILS_INFO("Resolved " << hostname << " to " << ip_str);
    return std::string(ip_str);
}

std::string resolve_hostname_v6(const std::string& hostname) {
    LOG_NETUTILS_DEBUG("Resolving hostname to IPv6: " << hostname);
    
    if (hostname.empty()) {
        LOG_NETUTILS_DEBUG("Empty hostname provided");
        return "";
    }
    
    if (is_valid_ipv6(hostname)) {
        LOG_NETUTILS_DEBUG("Already an IPv6 address: " << hostname);
        return hostname;
    }
    
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_DGRAM;
    
    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (status != 0) {
#ifdef _WIN32
        LOG_NETUTILS_DEBUG("Failed to resolve hostname " << hostname << " to IPv6: " << WSAGetLastError());
#else
        LOG_NETUTILS_DEBUG("Failed to resolve hostname " << hostname << " to IPv6: " << gai_strerror(status));
#endif
        return "";
    }
    
    char ip_str[INET6_ADDRSTRLEN];
    struct sockaddr_in6* addr_in6 = (struct sockaddr_in6*)result->ai_addr;
    inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, INET6_ADDRSTRLEN);
    
    freeaddrinfo(result);
    
    LOG_NETUTILS_DEBUG("Resolved " << hostname << " to IPv6 " << ip_str);
    return std::string(ip_str);
}

bool is_valid_ipv4(const std::string& ip_str) {
#ifdef __APPLE__
    // macOS-specific validation to handle inet_pton() accepting leading zeros
    std::vector<std::string> octets;
    std::string current_octet;
    
    for (char c : ip_str) {
        if (c == '.') {
            octets.push_back(current_octet);
            current_octet.clear();
        } else {
            current_octet += c;
        }
    }
    
    if (!current_octet.empty()) {
        octets.push_back(current_octet);
    }
    
    if (octets.size() != 4) {
        return false;
    }
    
    for (const std::string& octet : octets) {
        if (octet.empty()) {
            return false;
        }
        
        if (octet.length() > 1 && octet[0] == '0') {
            return false;
        }
        
        for (char c : octet) {
            if (c < '0' || c > '9') {
                return false;
            }
        }
        
        int value = std::stoi(octet);
        if (value < 0 || value > 255) {
            return false;
        }
    }
#endif
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip_str.c_str(), &sa.sin_addr) == 1;
}

bool is_valid_ipv6(const std::string& ip_str) {
    struct sockaddr_in6 sa;
    return inet_pton(AF_INET6, ip_str.c_str(), &sa.sin6_addr) == 1;
}

bool is_hostname(const std::string& str) {
    if (is_valid_ipv4(str) || is_valid_ipv6(str)) {
        return false;
    }
    
    if (str.empty() || str.length() > 253) {
        return false;
    }
    
    if (str.front() == '.' || str.back() == '.') {
        return false;
    }
    
    if (str.front() == '-' || str.back() == '-') {
        return false;
    }
    
    if (str.find("..") != std::string::npos) {
        return false;
    }
    
    if (str == ".") {
        return false;
    }
    
    for (char c : str) {
        if (c == ' ' || c == '@' || c == '#' || c == '$' || c == '%' || 
            c == '^' || c == '&' || c == '*' || c == '(' || c == ')' || 
            c == '+' || c == '=' || c == '[' || c == ']' || c == '{' || 
            c == '}' || c == '|' || c == '\\' || c == '/' || c == '?' || 
            c == '<' || c == '>' || c == ',' || c == ';' || c == ':' || 
            c == '"' || c == '\'' || c == '`' || c == '~' || c == '!') {
            return false;
        }
    }
    
    return true;
}

bool is_public_ip(const std::string& ip) {
    if (ip.empty()) return false;

    if (is_valid_ipv6(ip)) {
        struct in6_addr a;
        if (inet_pton(AF_INET6, ip.c_str(), &a) != 1) return false;
        const uint8_t* b = a.s6_addr;
        bool all_zero = true;
        for (int i = 0; i < 16; ++i) { if (b[i]) { all_zero = false; break; } }
        if (all_zero) return false;                              // ::  (unspecified)
        bool loopback = (b[15] == 1);
        for (int i = 0; i < 15; ++i) { if (b[i]) { loopback = false; break; } }
        if (loopback) return false;                              // ::1
        if ((b[0] & 0xfe) == 0xfc) return false;                 // fc00::/7  unique local
        if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return false; // fe80::/10 link-local
        if (b[0] == 0xff) return false;                          // ff00::/8  multicast
        return true;
    }

    struct in_addr a;
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return false;
    uint32_t h = ntohl(a.s_addr);
    uint8_t o1 = static_cast<uint8_t>((h >> 24) & 0xff);
    uint8_t o2 = static_cast<uint8_t>((h >> 16) & 0xff);
    if (o1 == 0) return false;                                   // 0.0.0.0/8
    if (o1 == 127) return false;                                 // loopback
    if (o1 == 10) return false;                                  // 10.0.0.0/8
    if (o1 == 172 && o2 >= 16 && o2 <= 31) return false;         // 172.16.0.0/12
    if (o1 == 192 && o2 == 168) return false;                    // 192.168.0.0/16
    if (o1 == 169 && o2 == 254) return false;                    // 169.254.0.0/16 link-local
    if (o1 == 100 && o2 >= 64 && o2 <= 127) return false;        // 100.64.0.0/10 CGNAT
    if (o1 >= 224) return false;                                 // multicast / reserved
    return true;
}

std::vector<std::string> get_local_interface_addresses() {
    LOG_NETUTILS_DEBUG("Getting all local interface addresses (IPv4 and IPv6)");
    
    std::vector<std::string> addresses;
    
    auto ipv4_addresses = get_local_interface_addresses_v4();
    addresses.insert(addresses.end(), ipv4_addresses.begin(), ipv4_addresses.end());
    
    auto ipv6_addresses = get_local_interface_addresses_v6();
    addresses.insert(addresses.end(), ipv6_addresses.begin(), ipv6_addresses.end());
    
    LOG_NETUTILS_INFO("Found " << addresses.size() << " total local interface addresses ("
                      << ipv4_addresses.size() << " IPv4, " << ipv6_addresses.size() << " IPv6)");

    return addresses;
}

namespace {

// Append unique, non-empty entries preserving order
void append_unique(std::vector<std::string>& out, const std::string& value) {
    if (value.empty()) return;
    if (std::find(out.begin(), out.end(), value) == out.end()) {
        out.push_back(value);
    }
}

// Best-effort guess: for each local IPv4 assume the gateway is the .1 host of a
// /24 network. Covers the overwhelming majority of home routers and serves as a
// fallback when the OS routing table is unavailable.
void append_gateway_heuristics(std::vector<std::string>& out) {
    for (const auto& ip : get_local_interface_addresses_v4()) {
        if (ip.empty() || ip == "127.0.0.1") continue;
        auto last_dot = ip.find_last_of('.');
        if (last_dot == std::string::npos) continue;
        append_unique(out, ip.substr(0, last_dot) + ".1");
    }
}

} // anonymous namespace

std::vector<std::string> get_default_gateways() {
    std::vector<std::string> gateways;

#ifdef _WIN32
    ULONG out_buf_len = sizeof(IP_ADAPTER_INFO);
    std::vector<uint8_t> buffer(out_buf_len);
    DWORD ret = GetAdaptersInfo(reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data()), &out_buf_len);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(out_buf_len);
        ret = GetAdaptersInfo(reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data()), &out_buf_len);
    }
    if (ret == NO_ERROR) {
        for (PIP_ADAPTER_INFO adapter = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
             adapter != nullptr; adapter = adapter->Next) {
            for (const IP_ADDR_STRING* gw = &adapter->GatewayList; gw != nullptr; gw = gw->Next) {
                std::string gw_ip(gw->IpAddress.String);
                if (gw_ip != "0.0.0.0") {
                    append_unique(gateways, gw_ip);
                }
            }
        }
    } else {
        LOG_NETUTILS_DEBUG("GetAdaptersInfo failed with error: " << ret);
    }
#elif defined(__linux__)
    // /proc/net/route columns: Iface Destination Gateway Flags ... (hex, little-endian)
    if (FILE* f = std::fopen("/proc/net/route", "r")) {
        char line[256];
        // Skip header line
        if (std::fgets(line, sizeof(line), f)) {
            char iface[64];
            unsigned long dest = 0, gw = 0;
            while (std::fgets(line, sizeof(line), f)) {
                if (std::sscanf(line, "%63s %lx %lx", iface, &dest, &gw) == 3) {
                    if (dest == 0 && gw != 0) {
                        struct in_addr addr;
                        addr.s_addr = static_cast<in_addr_t>(gw);
                        char ip_str[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str))) {
                            append_unique(gateways, ip_str);
                        }
                    }
                }
            }
        }
        std::fclose(f);
    }
#elif defined(RATS_HAVE_BSD_ROUTES)
    // Dump the IPv4 routing table and pick the gateway of the default route(s).
    int mib[6] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0 };
    size_t needed = 0;
    if (sysctl(mib, 6, nullptr, &needed, nullptr, 0) == 0 && needed > 0) {
        std::vector<char> buf(needed);
        if (sysctl(mib, 6, buf.data(), &needed, nullptr, 0) == 0) {
            // sockaddrs in a routing message are padded to a 4-byte boundary.
            auto sa_roundup = [](socklen_t len) -> size_t {
                return len ? (1 + ((static_cast<size_t>(len) - 1) | (sizeof(uint32_t) - 1)))
                           : sizeof(uint32_t);
            };
            char* lim = buf.data() + needed;
            for (char* next = buf.data(); next + sizeof(struct rt_msghdr) <= lim; ) {
                auto* rtm = reinterpret_cast<struct rt_msghdr*>(next);
                if (rtm->rtm_msglen == 0) break;
                char* msg_end = next + rtm->rtm_msglen;
                next = msg_end;

                if (!(rtm->rtm_flags & RTF_GATEWAY)) continue;
                if (!(rtm->rtm_addrs & RTA_DST) || !(rtm->rtm_addrs & RTA_GATEWAY)) continue;

                // Address list follows the header, ordered by the RTA_* bit flags.
                char* sa_ptr = reinterpret_cast<char*>(rtm + 1);
                struct sockaddr* dst = nullptr;
                struct sockaddr* gw = nullptr;
                for (int bit = 1; bit && sa_ptr < msg_end; bit <<= 1) {
                    if (!(rtm->rtm_addrs & bit)) continue;
                    auto* sa = reinterpret_cast<struct sockaddr*>(sa_ptr);
                    if (bit == RTA_DST) dst = sa;
                    else if (bit == RTA_GATEWAY) gw = sa;
                    sa_ptr += sa_roundup(sa->sa_len);
                }

                if (!dst || !gw) continue;
                if (dst->sa_family != AF_INET || gw->sa_family != AF_INET) continue;
                // Default route: destination 0.0.0.0
                if (reinterpret_cast<struct sockaddr_in*>(dst)->sin_addr.s_addr != 0) continue;

                char ip_str[INET_ADDRSTRLEN];
                auto* gw4 = reinterpret_cast<struct sockaddr_in*>(gw);
                if (inet_ntop(AF_INET, &gw4->sin_addr, ip_str, sizeof(ip_str))) {
                    append_unique(gateways, ip_str);
                }
            }
        }
    } else {
        LOG_NETUTILS_DEBUG("PF_ROUTE sysctl for default gateway failed");
    }
#endif

    // Always add heuristics as a fallback so callers have something to try
    append_gateway_heuristics(gateways);

    LOG_NETUTILS_INFO("Detected " << gateways.size() << " default gateway candidate(s)");
    return gateways;
}

} // namespace network_utils
} // namespace librats
