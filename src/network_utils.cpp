#ifdef _WIN32
    // Include winsock2.h first to avoid conflicts with windows.h
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

#include "network_utils.h"
#include "logger.h"
#include <cstring>
#include <iostream>

// Network utilities module logging macros
#define LOG_NETUTILS_DEBUG(message) LOG_DEBUG("network_utils", message)
#define LOG_NETUTILS_INFO(message)  LOG_INFO("network_utils", message)
#define LOG_NETUTILS_WARN(message)  LOG_WARN("network_utils", message)
#define LOG_NETUTILS_ERROR(message) LOG_ERROR("network_utils", message)

namespace librats {
namespace network_utils {

std::string resolve_hostname(const std::string& hostname) {
    LOG_NETUTILS_DEBUG("Resolving hostname: " << hostname);
    
    // Check if it's already an IP address
    if (is_valid_ipv4(hostname)) {
        LOG_NETUTILS_DEBUG("Already an IP address: " << hostname);
        return hostname;
    }
    
    // Resolve hostname using getaddrinfo
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // IPv4
    hints.ai_socktype = SOCK_DGRAM;  // UDP
    
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

bool is_valid_ipv4(const std::string& ip_str) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip_str.c_str(), &sa.sin_addr) == 1;
}

bool is_hostname(const std::string& str) {
    return !is_valid_ipv4(str);
}

std::string to_ip_address(const std::string& host) {
    return resolve_hostname(host);
}

std::vector<std::string> resolve_all_addresses(const std::string& hostname) {
    LOG_NETUTILS_DEBUG("Resolving all addresses for hostname: " << hostname);
    
    std::vector<std::string> addresses;
    
    // Check if it's already an IP address
    if (is_valid_ipv4(hostname)) {
        LOG_NETUTILS_DEBUG("Already an IP address: " << hostname);
        addresses.push_back(hostname);
        return addresses;
    }
    
    // Resolve hostname using getaddrinfo
    struct addrinfo hints, *result, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  // IPv4
    hints.ai_socktype = SOCK_DGRAM;  // UDP
    
    int status = getaddrinfo(hostname.c_str(), nullptr, &hints, &result);
    if (status != 0) {
#ifdef _WIN32
        LOG_NETUTILS_ERROR("Failed to resolve hostname " << hostname << ": " << WSAGetLastError());
#else
        LOG_NETUTILS_ERROR("Failed to resolve hostname " << hostname << ": " << gai_strerror(status));
#endif
        return addresses;
    }
    
    // Iterate through all addresses
    for (rp = result; rp != nullptr; rp = rp->ai_next) {
        char ip_str[INET_ADDRSTRLEN];
        struct sockaddr_in* addr_in = (struct sockaddr_in*)rp->ai_addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, INET_ADDRSTRLEN);
        
        std::string ip_address(ip_str);
        addresses.push_back(ip_address);
        LOG_NETUTILS_DEBUG("Found address: " << ip_address);
    }
    
    freeaddrinfo(result);
    
    LOG_NETUTILS_INFO("Resolved " << hostname << " to " << addresses.size() << " addresses");
    return addresses;
}

void demo_network_utils(const std::string& test_hostname) {
    LOG_NETUTILS_INFO("=== Network Utils Demo ===");
    LOG_NETUTILS_INFO("Testing with hostname: " << test_hostname);
    
    // Test if it's a hostname or IP
    if (is_hostname(test_hostname)) {
        LOG_NETUTILS_INFO("'" << test_hostname << "' is a hostname");
    } else {
        LOG_NETUTILS_INFO("'" << test_hostname << "' is an IP address");
    }
    
    // Test IP validation
    std::string test_ip = "192.168.1.1";
    LOG_NETUTILS_INFO("'" << test_ip << "' is valid IP: " << (is_valid_ipv4(test_ip) ? "yes" : "no"));
    
    // Test hostname resolution
    std::string resolved_ip = resolve_hostname(test_hostname);
    if (!resolved_ip.empty()) {
        LOG_NETUTILS_INFO("Resolved '" << test_hostname << "' to: " << resolved_ip);
    } else {
        LOG_NETUTILS_ERROR("Failed to resolve '" << test_hostname << "'");
    }
    
    // Test getting all addresses
    auto all_addresses = resolve_all_addresses(test_hostname);
    LOG_NETUTILS_INFO("Found " << all_addresses.size() << " addresses for '" << test_hostname << "':");
    for (size_t i = 0; i < all_addresses.size(); ++i) {
        LOG_NETUTILS_INFO("  [" << i << "] " << all_addresses[i]);
    }
    
    // Test to_ip_address (alias function)
    std::string ip_via_alias = to_ip_address(test_hostname);
    LOG_NETUTILS_INFO("to_ip_address('" << test_hostname << "') = " << ip_via_alias);
    
    LOG_NETUTILS_INFO("=== Demo Complete ===");
}

} // namespace network_utils
} // namespace librats 