#pragma once

#include <string>
#include <vector>

namespace librats {
namespace network_utils {

/**
 * Resolve hostname to IPv4 address
 * @param hostname The hostname to resolve (can be hostname or IP address)
 * @return IP address string, or empty string on error
 */
std::string resolve_hostname(const std::string& hostname);

/**
 * Resolve hostname to IPv6 address
 * @param hostname The hostname to resolve (can be hostname or IPv6 address)
 * @return IPv6 address string, or empty string on error
 */
std::string resolve_hostname_v6(const std::string& hostname);

/**
 * Check if a string is a valid IPv4 address
 * @param ip_str The string to validate
 * @return true if valid IPv4 address, false otherwise
 */
bool is_valid_ipv4(const std::string& ip_str);

/**
 * Check if a string is a valid IPv6 address
 * @param ip_str The string to validate
 * @return true if valid IPv6 address, false otherwise
 */
bool is_valid_ipv6(const std::string& ip_str);

/**
 * Check if a string is a hostname (not an IP address)
 * @param str The string to check
 * @return true if it's a hostname, false if it's an IP address
 */
bool is_hostname(const std::string& str);

/**
 * Get all local network interface addresses (IPv4 and IPv6)
 * @return Vector of local IP addresses from all network interfaces
 */
std::vector<std::string> get_local_interface_addresses();

} // namespace network_utils
} // namespace librats
